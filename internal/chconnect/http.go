package chconnect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/LucStr/chauth/internal/chapi"
	"github.com/LucStr/chauth/internal/chwire"
)

// ServeHTTP serves ClickHouse HTTP clients on ln until ctx ends; open requests then get 5 s.
func (c *Connector) ServeHTTP(ctx context.Context, ln net.Listener, env string) error {
	srv := &http.Server{Handler: c.HTTPHandler(env), ReadHeaderTimeout: handshakeTimeout}
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
	// database is the target without the environment; header says whether it came as X-ClickHouse-Database.
	database string
	header   bool
}

type forwardKey struct{}

// HTTPHandler forwards every path to the environment the request's database names, with the
// environment's token as Bearer and every client credential removed.
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
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f := r.Context().Value(forwardKey{}).(*forward)
			c.log.Error("forward to chauth", "server", f.env.HTTPServer.Host, "error", err)
			httpError(w, http.StatusBadGateway, chwire.CodeNetworkError, "chauth connect: cannot reach "+f.env.HTTPServer.Host)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, header, err := requestTarget(r)
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
		tok, err := e.Tokens.Token(r.Context())
		if err != nil {
			c.log.Error("no token", "env", e.Name, "error", err)
			httpError(w, http.StatusUnauthorized, chwire.CodeAccessDenied, err.Error())
			return
		}
		c.log.Info("request", "protocol", "http", "database", target+" → "+e.Name+":"+rest)
		f := &forward{env: e, token: tok, database: rest, header: header}
		proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), forwardKey{}, f)))
	})
}

// requestTarget is the database the client named: the database parameter or the X-ClickHouse-Database
// header, "" when neither is set; naming it twice is refused.
func requestTarget(r *http.Request) (string, bool, error) {
	params := r.URL.Query()["database"]
	headers := r.Header.Values("X-ClickHouse-Database")
	switch {
	case len(params)+len(headers) > 1:
		return "", false, errors.New("name the database once, as database= or X-ClickHouse-Database")
	case len(headers) == 1:
		return headers[0], true, nil
	case len(params) == 1:
		return params[0], false, nil
	}
	return "", false, nil
}

// credentialParams are URL parameters that would log in as someone else; ClickHouse matches them
// case-sensitively, but any letter case is removed.
var credentialParams = []string{"user", "password"}

func rewrite(out *http.Request, f *forward) {
	for _, h := range []string{"Authorization", "X-ClickHouse-User", "X-ClickHouse-Key", "X-ClickHouse-Database"} {
		out.Header.Del(h)
	}
	q := out.URL.Query()
	for k := range q {
		for _, p := range append(credentialParams, "database") {
			if strings.EqualFold(k, p) {
				q.Del(k)
			}
		}
	}
	if f.database != "" {
		if f.header {
			out.Header.Set("X-ClickHouse-Database", f.database)
		} else {
			q.Set("database", f.database)
		}
	}
	out.URL.RawQuery = q.Encode()
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
