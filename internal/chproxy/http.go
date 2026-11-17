package chproxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/netutil"

	"github.com/LucStr/chauth/internal/chapi"
	"github.com/LucStr/chauth/internal/chwire"
	"github.com/LucStr/chauth/internal/rbac"
	"github.com/LucStr/chauth/internal/token"
)

// Client credentials removed from every proxied request, compared ignoring case.
var (
	strippedParams  = []string{"user", "password", "quota_key", chapi.CORSParam}
	strippedHeaders = []string{"Authorization", "X-ClickHouse-User", "X-ClickHouse-Key", "X-ClickHouse-Quota",
		"X-ClickHouse-SSL-Certificate-Auth", "X-ClickHouse-Database"}
)

// LimitHTTP caps the open connections accepted from ln at limits.maxHTTPConnections; further
// clients wait in the accept queue.
func (s *Server) LimitHTTP(ln net.Listener) net.Listener {
	return netutil.LimitListener(ln, s.cfg.Limits.MaxHTTPConnections)
}

// NewHTTPServer is the HTTPS server for Handler with the pre-auth limits applied; the caller sets
// Addr or calls ServeTLS. There is no read or write timeout: bodies stream.
func (s *Server) NewHTTPServer() *http.Server {
	return &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         s.tls,
		ReadHeaderTimeout: time.Duration(s.cfg.Limits.HandshakeTimeout),
		IdleTimeout:       chapi.IdleTimeout,
		MaxHeaderBytes:    s.cfg.Limits.PreAuthMaxBytes,
	}
}

// Handler serves discovery, access and the ClickHouse HTTP interface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+chapi.DiscoveryPath, func(w http.ResponseWriter, r *http.Request) {
		closeAfter(w)
		s.discovery(w, r)
	})
	mux.HandleFunc("GET "+chapi.AccessPath, s.access)
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		closeAfter(w)
		_, _ = io.WriteString(w, "Ok.\n")
	})
	mux.HandleFunc("/", s.proxyHTTP)
	return mux
}

func (f *failure) httpStatus() int {
	switch f.kind {
	case badTarget:
		return http.StatusBadRequest
	case unavailable:
		return http.StatusServiceUnavailable
	case limited:
		return http.StatusTooManyRequests
	}
	if f.forbidden {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}

func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	defer s.requests.Done()
	ctx, finish, a := s.begin(r.Context(), "http")
	sw := &statusWriter{ResponseWriter: w}
	// fail answers f; reason, when set, is logged instead of f.msg.
	fail := func(f *failure, reason string) {
		closeAfter(w)
		a.status = f.httpStatus()
		finish(f.decision(), cmp.Or(reason, f.msg))
		if a.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="chauth"`)
		}
		w.Header().Set("X-ClickHouse-Exception-Code", strconv.Itoa(int(f.nativeCode())))
		http.Error(w, f.msg, a.status)
	}
	raw := requestToken(r)
	query, target, err := rewriteQuery(r)
	if err != nil {
		fail(&failure{kind: badTarget, msg: "chauth: " + err.Error()}, "")
		return
	}
	a.db = target
	in, d, f := s.decide(ctx, raw, target, a)
	if f != nil {
		fail(f, "")
		return
	}
	if !s.admit(d.Claims.Subject) {
		fail(&failure{kind: limited, msg: fmt.Sprintf("chauth: too many concurrent requests for %s (limit %d)", d.Claims.Username, s.cfg.Limits.MaxConnectionsPerUser)}, "")
		return
	}
	defer s.leave(d.Claims.Subject)
	lease, err := in.users.Acquire(ctx, d.key())
	if err != nil {
		fail(acquireFailure(err), err.Error())
		return
	}
	defer lease.Release()
	a.tempUser = lease.User
	query = chapi.AppendParam(query, "database", d.Database)
	queryID := queryIDOf(query)
	if queryID == "" {
		queryID = "chauth-" + rand.Text()
		query = chapi.AppendParam(query, "query_id", queryID)
	}
	completed := false
	defer func() {
		if completed {
			return
		}
		// ClickHouse over HTTPS notices a gone client only when the query next writes.
		kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := in.admin.CancelQuery(kctx, lease.User, lease.Password, queryID); err != nil {
			s.log.Warn("cancel the upstream query of a closed request", "temp_user", lease.User, "error", err)
		}
	}()

	var upstreamErr error
	rp := &httputil.ReverseProxy{
		Transport:     in.transport,
		FlushInterval: -1,
		ErrorLog:      slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = in.httpURL.Scheme, in.httpURL.Host
			pr.Out.URL.Path = path.Join("/", in.httpURL.Path, r.URL.Path)
			if strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(pr.Out.URL.Path, "/") {
				pr.Out.URL.Path += "/"
			}
			pr.Out.URL.RawPath, pr.Out.URL.RawQuery, pr.Out.Host = "", query, in.httpURL.Host
			for k := range pr.Out.Header {
				for _, h := range strippedHeaders {
					if strings.EqualFold(k, h) {
						delete(pr.Out.Header, k)
					}
				}
			}
			pr.SetXForwarded()
			pr.Out.SetBasicAuth(lease.User, lease.Password)
			chapi.NoReplay(pr.Out)
		},
		ModifyResponse: func(resp *http.Response) error {
			chapi.StripCORS(resp.Header)
			return hideLoginFailure(resp)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			upstreamErr = err
			http.Error(w, "chauth: the upstream request failed", http.StatusBadGateway)
		},
	}
	defer func() {
		a.status = sw.status
		if p := recover(); p != nil {
			finish("error", "response stream cut")
			panic(p)
		}
		if upstreamErr != nil {
			finish("error", upstreamErr.Error())
			return
		}
		finish("allow", "")
	}()
	rp.ServeHTTP(sw, r.WithContext(ctx))
	completed = r.Context().Err() == nil && upstreamErr == nil
}

// queryIDOf is the query_id parameter of a raw query, "" when there is none.
func queryIDOf(query string) string {
	_, ids, err := chapi.FilterQuery(query, "query_id", func(string) bool { return false })
	if err != nil || len(ids) == 0 {
		return ""
	}
	return ids[len(ids)-1]
}

// closeAfter ends the connection with this answer and stops reading the request: otherwise the
// server would wait for an unread body, so a client without a token could hold a connection slot.
func closeAfter(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
}

// hideLoginFailure replaces an upstream authentication error, which a retry may fix, with a 502.
func hideLoginFailure(resp *http.Response) error {
	if resp.StatusCode < 400 || resp.Header.Get("X-ClickHouse-Exception-Code") != strconv.Itoa(chwire.CodeAuthenticationFailed) {
		return nil
	}
	resp.Body.Close()
	msg := []byte("chauth: the upstream refused the temp user's login; retry the request\n")
	resp.Body = io.NopCloser(bytes.NewReader(msg))
	resp.ContentLength = int64(len(msg))
	resp.Header.Set("Content-Length", strconv.Itoa(len(msg)))
	resp.Header.Del("Content-Encoding")
	resp.StatusCode, resp.Status = http.StatusBadGateway, "502 Bad Gateway"
	return nil
}

// requestToken is the Bearer token, or the password of Basic auth.
func requestToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	scheme, value, _ := strings.Cut(h, " ")
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return strings.TrimSpace(value)
	case strings.EqualFold(scheme, "Basic"):
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return ""
		}
		_, pw, _ := strings.Cut(string(b), ":")
		return pw
	}
	return ""
}

// rewriteQuery drops every client credential, CORS and database parameter from the raw query,
// keeping the rest in order and as sent, and returns the target from the database parameter or header.
func rewriteQuery(r *http.Request) (string, string, error) {
	kept, targets, err := chapi.FilterQuery(r.URL.RawQuery, "database", func(k string) bool { return chapi.OneOf(k, strippedParams...) })
	if err != nil {
		return "", "", err
	}
	for k, vs := range r.Header {
		if strings.EqualFold(k, "X-ClickHouse-Database") {
			targets = append(targets, vs...)
		}
	}
	target := ""
	for i, t := range targets {
		if i > 0 && t != target {
			return "", "", errors.New("the database parameter and header disagree")
		}
		target = t
	}
	return kept, target, nil
}

// statusWriter records the status; Unwrap keeps flushing and aborting working through it.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	d := chapi.Discovery{
		Native: joinHostPort(host, s.cfg.Listen.Native), HTTP: "https://" + joinHostPort(host, s.cfg.Listen.HTTP),
		Issuer: s.cfg.OIDC.Issuer, Audience: s.cfg.OIDC.Audience,
		Scopes:     chapi.Scopes{Read: s.cfg.OIDC.Scopes.Read, Write: s.cfg.OIDC.Scopes.Write},
		AccessHelp: s.cfg.AccessHelp, Instances: []chapi.Instance{},
	}
	for _, in := range s.cfg.Instances {
		d.Instances = append(d.Instances, chapi.Instance{Name: in.Name, Databases: in.Databases, Roles: nonNil(in.Roles)})
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chauth"`)
		closeAfter(w)
		writeJSON(w, http.StatusUnauthorized, chapi.Error{Error: "send the database token as Authorization: Bearer <token>"})
		return
	}
	claims, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		code := http.StatusUnauthorized
		if !errors.Is(err, token.ErrDenied) {
			code = http.StatusInternalServerError
		}
		closeAfter(w)
		writeJSON(w, code, chapi.Error{Error: err.Error()})
		return
	}
	policy := s.rbac.Policy()
	if policy == nil {
		closeAfter(w)
		writeJSON(w, http.StatusServiceUnavailable, chapi.Error{Error: "access rules are not loaded"})
		return
	}
	scopeCap := rbac.ScopeCap(claims.Scopes, s.cfg.OIDC.Scopes.Read, s.cfg.OIDC.Scopes.Write)
	who := rbac.Who{User: claims.Username, Groups: claims.Groups, FoldUser: s.cfg.OIDC.FoldUsername()}
	out := []chapi.Access{}
	for _, in := range s.cfg.Instances {
		g := grants(policy, who, in, scopeCap)
		e := chapi.Access{Instance: in.Name, Databases: []chapi.DatabaseAccess{}, Roles: nonNil(g.Roles)}
		for _, db := range in.Databases {
			if lv := g.Databases[db]; lv > rbac.None {
				e.Databases = append(e.Databases, chapi.DatabaseAccess{Database: db, Level: lv.String()})
			}
		}
		if len(e.Databases) == 0 && len(e.Roles) == 0 {
			continue
		}
		e.Level = level(policy, who, in.Name, scopeCap, g).String()
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// joinHostPort is host with the port of the listen address addr.
func joinHostPort(host, addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return net.JoinHostPort(host, port)
}
