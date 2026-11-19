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
	cfg        chconfig.Instance
	ready      atomic.Bool
	admin      *chusers.Admin
	users      *chusers.Manager
	selfTest   func(context.Context) error
	readGrants func(context.Context) error
	// upstream holds the template roles' own grants and the row-policy databases, read after each
	// passing self-test; run rows
	// keep only the verbs the binding's role holds.
	upstream  atomic.Pointer[rbac.Upstream]
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
		inst := &instance{
			cfg: in, admin: admin, httpURL: u,
			transport: &http.Transport{TLSClientConfig: upTLS, MaxIdleConnsPerHost: 64, IdleConnTimeout: time.Minute, DisableCompression: true},
			users: chusers.NewManager(admin, in, chusers.Options{
				LeaseDuration: time.Duration(l.LeaseDuration), MaxConnectionAge: time.Duration(l.MaxConnectionAge),
				IdleTTL: time.Duration(l.TempUserIdleTTL), MaxRefs: l.MaxConnectionsPerTempUser, Log: log,
			}),
		}
		roles, tables, templates := in.GrantableRoles(), in.GrantableTables(), in.TemplateRoles()
		inst.selfTest = func(ctx context.Context) error { return inst.users.SelfTest(ctx, roles, tables) }
		inst.readGrants = func(ctx context.Context) error {
			u, err := inst.admin.Upstream(ctx, templates)
			if err == nil {
				inst.upstream.Store(u)
			}
			return err
		}
		s.instances[in.Name] = inst
	}
	return s, nil
}

// Start makes each instance ready once the admin login, a sweep of expired temp users and a self-test
// pass; the self-test then repeats every selfTestInterval and gates readiness.
func (s *Server) Start(ctx context.Context) {
	for _, in := range s.instances {
		go s.watch(ctx, in)
	}
}

const (
	// failuresToUnready consecutive failed checks make a ready instance not ready.
	failuresToUnready = 3
	maxRetryWait      = 5 * time.Second
)

// watch checks in until ctx ends: not ready until the first pass, then not ready only after
// failuresToUnready failures in a row, retried a second apart; one pass makes it ready again.
func (s *Server) watch(ctx context.Context, in *instance) {
	interval := time.Duration(s.cfg.Limits.SelfTestInterval)
	swept, fails, logged := -1, 0, ""
	for wait := time.Second; ; {
		step, err := "admin login", in.admin.Ping(ctx)
		if err == nil && swept < 0 {
			step = "sweep"
			if swept, err = in.users.Sweep(ctx); err == nil {
				go in.users.Run(ctx, time.Duration(s.cfg.Limits.SweepInterval))
			} else {
				swept = -1
			}
		}
		if err == nil {
			step, err = "self-test", in.selfTest(ctx)
			if se := (*chusers.StepError)(nil); errors.As(err, &se) {
				step, err = "self-test: "+se.Step, se.Err
			}
		}
		if err == nil {
			if err = in.readGrants(ctx); err != nil {
				step = "read role grants"
			}
		}
		if ctx.Err() != nil {
			return
		}
		next := interval
		switch {
		case err == nil:
			fails, wait = 0, time.Second
			in.ready.Store(true)
			if logged != "ready" {
				logged = "ready"
				s.log.Info("instance ready", "instance", in.cfg.Name, "roles", in.cfg.GrantableRoles(), "swept", swept, "pod", in.users.Nonce())
			}
		case logged == "ready" && fails+1 < failuresToUnready:
			fails, next = fails+1, time.Second
		default:
			fails++
			in.ready.Store(false)
			if logged != "not ready" {
				logged = "not ready"
				s.log.Warn("instance not ready", "instance", in.cfg.Name, "step", step, "error", err, "failures", fails)
			}
			next, wait = min(wait, interval), min(2*wait, maxRetryWait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// Ready reports whether the issuer's keys and a valid set of access rules are loaded and every
// instance passed its last self-test and accepts the admin login.
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
	Roles []string
	// Tables are the temp user's direct table privileges, from the token's run intent.
	Tables   []rbac.TableGrant
	Bindings []string
}

func (d Decision) key() chusers.Key {
	return chusers.Key{Subject: d.Claims.Subject, Email: d.Claims.Username, Level: d.Level, Roles: d.Roles, Tables: d.Tables}
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
	r := reachOf(policy, who, cfgIn, d.ScopeCap, claims.Details, in.grants())
	d.Roles, d.Bindings, d.Level, d.Tables = cfgIn.UpstreamRoles(r.Granted), r.Bindings, r.level, r.tables
	a.bindings, a.roles, a.level, a.tables = d.Bindings, d.Roles, d.Level.String(), tableNames(d.Tables)
	if db != chconfig.DefaultDatabase && r.Databases[db] == rbac.None && !slices.Contains(cfgIn.Databases, db) {
		return nil, d, &failure{kind: badTarget, msg: fmt.Sprintf("chauth: serves no database %s/%s", cfgIn.Name, db)}
	}
	if len(d.Roles) == 0 && len(d.Tables) == 0 || db != chconfig.DefaultDatabase && !r.reaches(db) {
		msg := s.denial(cfgIn.Name, db, claims.Username)
		if why := r.denied[db]; why != "" {
			msg = fmt.Sprintf("chauth: no access to %s/%s for %s: %s.", cfgIn.Name, db, claims.Username, why)
		}
		return nil, d, &failure{kind: denied, forbidden: true, msg: msg}
	}
	return in, d, nil
}

// reach is what one token gets on one instance: the bindings capped by scope and readOnlyDatabases,
// narrowed by the token's authorization_details. Databases reached only through tables are not in Databases.
type reach struct {
	rbac.Granted
	tables []rbac.TableGrant
	level  rbac.Level
	// denied holds, per database the bindings gave, why authorization_details took it away.
	denied map[string]string
}

// grants are in's upstream grants and row policies, nil before the first read.
func (in *instance) grants() *rbac.Upstream { return in.upstream.Load() }

func reachOf(p *rbac.Policy, who rbac.Who, in chconfig.Instance, scopeCap rbac.Level, details []token.Detail, upstream *rbac.Upstream) reach {
	// Bindings stay as the rules gave them, before authorization_details removed any database.
	r := reach{Granted: grants(p, who, in, scopeCap), denied: map[string]string{}}
	roleCap := rbac.RoleCap(scopeCap, details)
	if details != nil {
		r.Roles = p.Grants(who, in.Name, roleCap).Roles
		for db, lv := range r.Databases {
			acc, err := rbac.Effective(lv, scopeCap, details, db)
			switch {
			case err != nil:
				r.denied[db] = err.Error()
				delete(r.Databases, db)
			case acc.Tables != nil:
				role := in.RoleFor(db, lv)
				held := slices.DeleteFunc(acc.Tables, func(t rbac.TableGrant) bool { return !upstream.Holds(role, t) })
				if len(held) == 0 {
					r.denied[db] = fmt.Sprintf("role %s holds none of the declared table verbs, or the database has a row policy", role)
				}
				r.tables = append(r.tables, held...)
				delete(r.Databases, db)
			case acc.Level == rbac.None:
				delete(r.Databases, db)
			default:
				r.Databases[db] = acc.Level
			}
		}
		slices.SortFunc(r.tables, func(a, b rbac.TableGrant) int { return strings.Compare(tableName(a), tableName(b)) })
	}
	r.level = level(p, who, in.Name, roleCap, r.Granted)
	for _, t := range r.tables {
		r.level = max(r.level, rbac.VerbLevel(t.Verb))
	}
	return r
}

// reaches reports whether the token gets anything on db, the whole database or some of its tables.
func (r reach) reaches(db string) bool {
	return r.Databases[db] > rbac.None || slices.ContainsFunc(r.tables, func(t rbac.TableGrant) bool { return t.Database == db })
}

func tableName(t rbac.TableGrant) string { return t.Database + "." + t.Table + ":" + t.Verb }

func tableNames(ts []rbac.TableGrant) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = tableName(t)
	}
	return out
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
	groups, bindings, roles, tables                       []string
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
			attribute.StringSlice("chauth.tables", a.tables),
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
			"instance", a.instance, "db", a.db, "bindings", a.bindings, "roles", a.roles, "tables", a.tables, "level", a.level, "scope_cap", a.scopeCap,
			"decision", decision, "reason", reason, "temp_user", a.tempUser, "protocol", a.protocol, "duration_ms", time.Since(start).Milliseconds()}
		if a.status != 0 {
			args = append(args, "status", a.status)
		}
		s.log.InfoContext(ctx, "connect", args...)
	}, a
}
