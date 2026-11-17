// Package chproxy serves ClickHouse's native protocol over TLS and its HTTP interface over HTTPS
// for clients that log in with a database token, as a temp user holding exactly the token's roles.
package chproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/chusers"
	"github.com/LucStr/chauth/internal/rbac"
	"github.com/LucStr/chauth/internal/token"
)

type Server struct {
	cfg      *chconfig.Config
	verifier *token.Verifier
	rbac     *rbac.Store
	tls      *tls.Config
	log      *slog.Logger
	tracer   trace.Tracer

	instances map[string]*instance
	conns     sync.WaitGroup
	stopping  chan struct{}
	stopOnce  sync.Once
	preAuth   *preAuth
	// open are the native connections Stop closes; requests counts running HTTP handlers.
	openMu   sync.Mutex
	open     map[net.Conn]bool
	requests sync.WaitGroup

	userMu    sync.Mutex
	userConns map[string]int
}

type instance struct {
	cfg       chconfig.Instance
	ready     atomic.Bool
	admin     *chusers.Admin
	users     *chusers.Manager
	httpURL   *url.URL
	transport *http.Transport
}

// New checks every instance's upstream settings; it connects to nothing until Start.
func New(cfg *chconfig.Config, verifier *token.Verifier, store *rbac.Store, tlsConfig *tls.Config, log *slog.Logger) (*Server, error) {
	s := &Server{
		cfg: cfg, verifier: verifier, rbac: store, tls: tlsConfig, log: log,
		tracer:    otel.Tracer("github.com/LucStr/chauth/internal/chproxy"),
		instances: map[string]*instance{}, stopping: make(chan struct{}), userConns: map[string]int{},
		preAuth: &preAuth{max: cfg.Limits.MaxPreAuthConnections, maxPerIP: cfg.Limits.MaxPreAuthConnectionsPerIP, perIP: map[string]int{}},
		open:    map[net.Conn]bool{},
	}
	l := cfg.Limits
	for _, in := range cfg.Instances {
		admin, err := chusers.NewAdmin(in)
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", in.Name, err)
		}
		u, err := url.Parse(in.HTTP)
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", in.Name, err)
		}
		upTLS, err := in.TLSConfig(u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", in.Name, err)
		}
		s.instances[in.Name] = &instance{
			cfg: in, admin: admin, httpURL: u,
			transport: &http.Transport{TLSClientConfig: upTLS, MaxIdleConnsPerHost: 64, IdleConnTimeout: time.Minute, DisableCompression: true},
			users: chusers.NewManager(admin, in, chusers.Options{
				LeaseDuration: time.Duration(l.LeaseDuration), MaxConnectionAge: time.Duration(l.MaxConnectionAge),
				IdleTTL: time.Duration(l.TempUserIdleTTL), MaxRefs: l.MaxConnectionsPerTempUser, Log: log,
			}),
		}
	}
	return s, nil
}

// Start logs in to every instance as the admin, sweeps expired temp users and starts the periodic
// sweep, retrying until each succeeds; an instance refuses connections until then.
func (s *Server) Start(ctx context.Context) {
	for _, in := range s.instances {
		go func() {
			for wait := time.Second; ; wait = min(2*wait, 30*time.Second) {
				err := in.admin.Ping(ctx)
				if err == nil {
					var n int
					if n, err = in.users.Sweep(ctx); err == nil {
						go in.users.Run(ctx, time.Duration(s.cfg.Limits.SweepInterval))
						in.ready.Store(true)
						s.log.Info("instance ready", "instance", in.cfg.Name, "swept", n, "pod", in.users.Nonce())
						return
					}
				}
				s.log.Warn("instance not ready", "instance", in.cfg.Name, "error", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}()
	}
}

// Ready reports whether the issuer's keys and a valid set of access rules are loaded and every
// instance accepts the admin login.
func (s *Server) Ready(ctx context.Context) error {
	if !s.verifier.Ready() {
		return errors.New("oidc keys not loaded")
	}
	if st := s.rbac.Status(); !st.Loaded {
		if st.Rejected != nil {
			return fmt.Errorf("no valid access rules loaded: %w", st.Rejected)
		}
		return errors.New("access rules not loaded")
	}
	for name, in := range s.instances {
		if !in.ready.Load() {
			return fmt.Errorf("instance %s not ready", name)
		}
		if err := in.admin.Ping(ctx); err != nil {
			return fmt.Errorf("instance %s: %w", name, err)
		}
	}
	return nil
}

// Stop stops accepting native connections and cuts every open one; ServeNative returns once they
// are closed.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		s.openMu.Lock()
		close(s.stopping)
		for c := range s.open {
			c.Close()
		}
		s.openMu.Unlock()
	})
}

func (s *Server) stopped() bool {
	select {
	case <-s.stopping:
		return true
	default:
		return false
	}
}

// track registers a native connection for Stop; false once stopping.
func (s *Server) track(c net.Conn) bool {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if s.stopped() {
		return false
	}
	s.open[c] = true
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.openMu.Lock()
	delete(s.open, c)
	s.openMu.Unlock()
}

// WaitRequests returns once every HTTP handler returned; call it after the HTTP server was closed.
func (s *Server) WaitRequests() { s.requests.Wait() }

// Close drops every temp user this process created; call it after the listeners stopped.
func (s *Server) Close(ctx context.Context) {
	for _, in := range s.instances {
		in.users.Close(ctx)
	}
}

// Failure kinds, each with its native error code and HTTP status.
type kind int

const (
	denied      kind = iota // token or grant: 497, 401/403
	badTarget               // 81, 400
	unavailable             // 210, 502/503
	limited                 // 202, 429
)

type failure struct {
	kind kind
	// forbidden marks a valid token without a grant: HTTP 403 instead of 401.
	forbidden bool
	msg       string
}

// acquireFailure is what the client is told when no temp user could be had.
func acquireFailure(err error) *failure {
	if errors.Is(err, chusers.ErrBadKey) {
		return &failure{kind: denied, forbidden: true, msg: "chauth: " + err.Error()}
	}
	return &failure{kind: unavailable, msg: "chauth: could not prepare the upstream login"}
}

func (f *failure) decision() string {
	if f.kind == unavailable {
		return "error"
	}
	return "deny"
}

// Decision is what one verified token may do on one target.
type Decision struct {
	Claims   token.Claims
	Instance string
	Database string
	// Level is the temp user's level: write when any database or named role is reached at write.
	Level    rbac.Level
	ScopeCap rbac.Level
	// Roles are the upstream roles of the temp user, sorted.
	Roles    []string
	Bindings []string
}

func (d Decision) key() chusers.Key {
	return chusers.Key{Subject: d.Claims.Subject, Email: d.Claims.Username, Level: d.Level, Roles: d.Roles}
}

// decide verifies raw and resolves target into what the token's holder gets there.
func (s *Server) decide(ctx context.Context, raw, target string, a *attempt) (*instance, Decision, *failure) {
	var d Decision
	if raw == "" {
		return nil, d, &failure{kind: denied, msg: "chauth: send the database token as the password"}
	}
	claims, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, d, &failure{kind: denied, msg: "chauth: " + err.Error()}
	}
	d.Claims = claims
	a.sub, a.user, a.groups, a.clientID = claims.Subject, claims.Username, claims.Groups, claims.ClientID
	cfgIn, db, err := s.cfg.Resolve(target)
	if err != nil {
		return nil, d, &failure{kind: badTarget, msg: "chauth: " + err.Error()}
	}
	d.Instance, d.Database = cfgIn.Name, db
	a.instance, a.db = cfgIn.Name, db
	in := s.instances[cfgIn.Name]
	if !in.ready.Load() {
		return nil, d, &failure{kind: unavailable, msg: fmt.Sprintf("chauth: instance %s is not ready", cfgIn.Name)}
	}
	policy := s.rbac.Policy()
	if policy == nil {
		return nil, d, &failure{kind: unavailable, msg: "chauth: access rules are not loaded"}
	}
	who := rbac.Who{User: claims.Username, Groups: claims.Groups, FoldUser: s.cfg.OIDC.FoldUsername()}
	d.ScopeCap = rbac.ScopeCap(claims.Scopes, s.cfg.OIDC.Scopes.Read, s.cfg.OIDC.Scopes.Write)
	a.scopeCap = d.ScopeCap.String()
	if d.ScopeCap == rbac.None {
		return nil, d, &failure{kind: denied, forbidden: true,
			msg: fmt.Sprintf("chauth: token has neither the %s nor the %s scope", s.cfg.OIDC.Scopes.Read, s.cfg.OIDC.Scopes.Write)}
	}
	g := grants(policy, who, cfgIn, d.ScopeCap)
	d.Roles, d.Bindings, d.Level = cfgIn.UpstreamRoles(g), g.Bindings, level(policy, who, cfgIn.Name, d.ScopeCap, g)
	a.bindings, a.roles, a.level = d.Bindings, d.Roles, d.Level.String()
	if db != chconfig.DefaultDatabase && g.Databases[db] == rbac.None && !slices.Contains(cfgIn.Databases, db) {
		return nil, d, &failure{kind: badTarget, msg: fmt.Sprintf("chauth: serves no database %s/%s", cfgIn.Name, db)}
	}
	if len(d.Roles) == 0 || db != chconfig.DefaultDatabase && g.Databases[db] == rbac.None {
		return nil, d, &failure{kind: denied, forbidden: true, msg: s.denial(cfgIn.Name, db, claims.Username)}
	}
	return in, d, nil
}

// grants is what who reaches on in after the scope cap, with every read-only database at most read.
func grants(p *rbac.Policy, who rbac.Who, in chconfig.Instance, scopeCap rbac.Level) rbac.Granted {
	g := p.Grants(who, in.Name, scopeCap)
	for db, lv := range g.Databases {
		g.Databases[db] = in.Cap(db, lv)
	}
	return g
}

// level is write when a database or a named role is reached at write; a named role counts as write
// when only the write scope cap reaches it.
func level(p *rbac.Policy, who rbac.Who, instance string, scopeCap rbac.Level, g rbac.Granted) rbac.Level {
	lv := rbac.None
	for _, l := range g.Databases {
		lv = max(lv, l)
	}
	if len(g.Roles) == 0 {
		return lv
	}
	lv = max(lv, rbac.Read)
	if scopeCap == rbac.Write {
		atRead := p.Grants(who, instance, rbac.Read).Roles
		for _, r := range g.Roles {
			if !slices.Contains(atRead, r) {
				return rbac.Write
			}
		}
	}
	return lv
}

// denial is the one-line reason a holder without a binding is refused, with where to ask for access.
func (s *Server) denial(instance, db, user string) string {
	msg := fmt.Sprintf("chauth: no access to %s/%s for %s: no binding grants it.", instance, db, user)
	if help := strings.Join(strings.Fields(s.cfg.AccessHelp), " "); help != "" {
		msg += " " + help
	}
	return msg
}

// admit counts one more connection or request for subject unless that would pass the limit.
func (s *Server) admit(subject string) bool {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if s.userConns[subject] >= s.cfg.Limits.MaxConnectionsPerUser {
		return false
	}
	s.userConns[subject]++
	return true
}

func (s *Server) leave(subject string) {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if s.userConns[subject]--; s.userConns[subject] <= 0 {
		delete(s.userConns, subject)
	}
}

// attempt collects what one connection or request logs and records on its span.
type attempt struct {
	protocol, sub, user, clientID, instance, db, tempUser string
	groups, bindings, roles                               []string
	level, scopeCap                                       string
	status                                                int
}

func (s *Server) begin(parent context.Context, protocol string) (context.Context, func(decision, reason string), *attempt) {
	start := time.Now()
	ctx, span := s.tracer.Start(parent, "chauth."+protocol, trace.WithSpanKind(trace.SpanKindServer))
	a := &attempt{protocol: protocol}
	done := false
	return ctx, func(decision, reason string) {
		if done {
			return
		}
		done = true
		attrs := []attribute.KeyValue{
			attribute.String("chauth.sub", a.sub),
			attribute.String("chauth.user", a.user),
			attribute.StringSlice("chauth.groups", a.groups),
			attribute.String("chauth.client_id", a.clientID),
			attribute.String("chauth.instance", a.instance),
			attribute.String("db.namespace", a.db),
			attribute.StringSlice("chauth.bindings", a.bindings),
			attribute.StringSlice("chauth.roles", a.roles),
			attribute.String("chauth.level", a.level),
			attribute.String("chauth.scope_cap", a.scopeCap),
			attribute.String("chauth.decision", decision),
			attribute.String("chauth.reason", reason),
			attribute.String("chauth.temp_user", a.tempUser),
			attribute.String("chauth.protocol", a.protocol),
		}
		if a.status != 0 {
			attrs = append(attrs, attribute.Int("http.response.status_code", a.status))
		}
		span.SetAttributes(attrs...)
		if decision != "allow" {
			span.SetStatus(codes.Error, reason)
		}
		span.End()
		args := []any{"sub", a.sub, "user", a.user, "groups", a.groups, "client_id", a.clientID,
			"instance", a.instance, "db", a.db, "bindings", a.bindings, "roles", a.roles, "level", a.level, "scope_cap", a.scopeCap,
			"decision", decision, "reason", reason, "temp_user", a.tempUser, "protocol", a.protocol, "duration_ms", time.Since(start).Milliseconds()}
		if a.status != 0 {
			args = append(args, "status", a.status)
		}
		s.log.InfoContext(ctx, "connect", args...)
	}, a
}
