package chconnect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/LucStr/chauth/internal/chapi"
	"github.com/LucStr/chauth/internal/chwire"
	"github.com/LucStr/chauth/internal/connect"
)

// ServeHTTP serves ClickHouse HTTP clients on ln until ctx ends; open requests then get 5 s.
func (c *Connector) ServeHTTP(ctx context.Context, ln net.Listener, env string) error {
	srv := &http.Server{Handler: c.HTTPHandler(env), ReadHeaderTimeout: handshakeTimeout, IdleTimeout: chapi.IdleTimeout}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			_ = srv.Close()
		}
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type forward struct {
	env   *Env
	token string
	// query is the client's raw query without credentials and database; database is the target
	// without the environment, sent as X-ClickHouse-Database when header is set.
	query    string
	database string
	header   bool
}

type forwardKey struct{}

// HTTPHandler forwards every path to the environment the request's database names, with the
// environment's token as Bearer and every client credential removed. It serves programs, not web
// pages: a request from a browser page or for a host name other than loopback is refused.
func (c *Connector) HTTPHandler(env string) http.Handler {
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1,
		ErrorLog:      slog.NewLogLogger(c.log.Handler(), slog.LevelWarn),
		Transport:     envTransport{},
		Rewrite: func(pr *httputil.ProxyRequest) {
			f := pr.In.Context().Value(forwardKey{}).(*forward)
			pr.SetURL(f.env.HTTPServer)
			rewrite(pr.Out, f)
			chapi.NoReplay(pr.Out)
		},
		ModifyResponse: func(resp *http.Response) error {
			chapi.StripCORS(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f := r.Context().Value(forwardKey{}).(*forward)
			c.log.Error("forward to chauth", "server", f.env.HTTPServer.Host, "error", err)
			httpError(w, http.StatusBadGateway, chwire.CodeNetworkError, "chauth connect: cannot reach "+f.env.HTTPServer.Host)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reason := fromBrowser(r); reason != "" {
			c.log.Warn("request refused", "protocol", "http", "reason", reason)
			httpError(w, http.StatusForbidden, chwire.CodeAccessDenied, "chauth connect: "+reason+"; the local port serves ClickHouse clients, not web pages")
			return
		}
		query, target, header, err := requestTarget(r)
		if err != nil {
			httpError(w, http.StatusBadRequest, chwire.CodeUnknownDatabase, "chauth connect: "+err.Error())
			return
		}
		e, rest, err := c.route(target, env)
		if err != nil {
			c.log.Info("request refused", "protocol", "http", "database", target, "reason", err)
			httpError(w, http.StatusBadRequest, chwire.CodeUnknownDatabase, "chauth connect: "+err.Error())
			return
		}
		tok, err := tokenWithoutLogin(r.Context(), e)
		if err != nil {
			c.log.Error("no token", "env", e.Name, "error", err)
			httpError(w, http.StatusUnauthorized, chwire.CodeAccessDenied, err.Error())
			return
		}
		c.log.Info("request", "protocol", "http", "database", target+" → "+e.Name+":"+rest)
		f := &forward{env: e, token: tok, query: query, database: rest, header: header}
		proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), forwardKey{}, f)))
	})
}

// tokenWithoutLogin never opens a browser: an HTTP request may come from anything that reaches the
// port, so a missing login is reported instead.
func tokenWithoutLogin(ctx context.Context, e *Env) (string, error) {
	src, ok := e.Tokens.(interface {
		TokenWithoutLogin(context.Context) (string, error)
	})
	if !ok {
		return e.Tokens.Token(ctx)
	}
	tok, err := src.TokenWithoutLogin(ctx)
	if errors.Is(err, connect.ErrLoginRequired) {
		return "", fmt.Errorf("chauth connect: not logged in to %s; run chauth login %s", e.Name, e.Name)
	}
	return tok, err
}

// fromBrowser is why r looks like it was sent by a web page, "" when it does not. A browser sends
// Origin or Sec-Fetch-Site; a host name other than a loopback literal is DNS rebinding.
func fromBrowser(r *http.Request) string {
	if _, ok := r.Header["Origin"]; ok {
		return "request has an Origin header"
	}
	if v, ok := r.Header["Sec-Fetch-Site"]; ok && (len(v) != 1 || v[0] != "none") {
		return "request comes from a web page"
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if local == nil || !loopbackHost(r.Host, local) {
		return fmt.Sprintf("host %q is not this listener's loopback address", r.Host)
	}
	return ""
}

// loopbackHost reports whether host is localhost or a loopback IP literal with local's port; the
// port may be left out only when it is 80.
func loopbackHost(host string, local net.Addr) bool {
	tcp, ok := local.(*net.TCPAddr)
	if !ok {
		return false
	}
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		name, port = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), "80"
		if strings.Contains(name, ":") && !strings.HasPrefix(host, "[") {
			return false
		}
	}
	if port != strconv.Itoa(tcp.Port) {
		return false
	}
	if strings.EqualFold(name, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(name)
	return err == nil && ip.Zone() == "" && ip.IsLoopback()
}

// requestTarget removes the credential, CORS and database parameters from the raw query, keeping
// the rest as sent, and returns the database the client named: parameter or header, "" when neither.
func requestTarget(r *http.Request) (query, target string, header bool, err error) {
	query, params, err := chapi.FilterQuery(r.URL.RawQuery, "database", func(k string) bool { return chapi.OneOf(k, droppedParams...) })
	if err != nil {
		return "", "", false, err
	}
	headers := r.Header.Values("X-ClickHouse-Database")
	switch {
	case len(params) > 1 || len(headers) > 1:
		return "", "", false, errors.New("name the database once, as database= or X-ClickHouse-Database")
	case len(params) == 1 && len(headers) == 1 && params[0] != headers[0]:
		return "", "", false, errors.New("the database parameter and the X-ClickHouse-Database header disagree")
	case len(params) == 1:
		return query, params[0], false, nil
	case len(headers) == 1:
		return query, headers[0], true, nil
	}
	return query, "", false, nil
}

// droppedParams would log in as someone else or make the answer readable by a web page; ClickHouse
// matches them case-sensitively, but any letter case is removed.
var droppedParams = []string{"user", "password", chapi.CORSParam}

// droppedHeaders are client credentials and what a browser adds; none of it is meant for serve.
var droppedHeaders = []string{"Authorization", "X-ClickHouse-User", "X-ClickHouse-Key", "X-ClickHouse-Database",
	"Origin", "Referer", "Cookie"}

func rewrite(out *http.Request, f *forward) {
	for k := range out.Header {
		if chapi.OneOf(k, droppedHeaders...) || len(k) >= 10 && strings.EqualFold(k[:10], "Sec-Fetch-") {
			delete(out.Header, k)
		}
	}
	query := f.query
	if f.database != "" {
		if f.header {
			out.Header.Set("X-ClickHouse-Database", f.database)
		} else {
			query = chapi.AppendParam(query, "database", f.database)
		}
	}
	out.URL.RawQuery = query
	out.Header.Set("Authorization", "Bearer "+f.token)
}

// envTransport sends each request with its environment's client transport.
type envTransport struct{}

func (envTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f := r.Context().Value(forwardKey{}).(*forward)
	return f.env.HTTP.Transport.RoundTrip(r)
}

// httpError answers the way ClickHouse does, so clients show the message.
func httpError(w http.ResponseWriter, status int, code int32, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Header().Set("X-ClickHouse-Exception-Code", fmt.Sprint(code))
	w.WriteHeader(status)
	fmt.Fprintf(w, "Code: %d. %s: %s. (%s)\n", code, chwire.ExceptionName, msg, chwire.CodeName(code))
}
