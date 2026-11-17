// Package chconnect is chauth's connector: it serves ClickHouse clients on localhost, picks the
// environment from the database name and forwards native and HTTP traffic to chauth serve with
// the environment's token.
package chconnect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/LucStr/chauth/internal/connect"
)

// Env is one chauth deployment: its native and HTTPS addresses and where its tokens come from.
type Env struct {
	Name string
	// Server is serve's native TLS host:port; HTTPServer its https:// base URL.
	Server     string
	HTTPServer *url.URL
	TLS        *tls.Config
	// HTTP talks to HTTPServer, for proxied requests and the API alike; it never retries a request.
	HTTP   *http.Client
	Tokens connect.TokenSource
}

// Options carry what the environments' browser logins need.
type Options struct {
	Store        connect.TokenStore
	OpenBrowser  func(url string) error
	CallbackPort int
	Log          *slog.Logger
}

// BuildEnvs turns a config checked by connect.File.Validate into environments.
func BuildEnvs(f *connect.File, o Options) ([]*Env, error) {
	var envs []*Env
	for _, name := range f.EnvNames() {
		ec := f.Environments[name]
		ca := ec.ServerCA
		if ca == "" {
			ca = f.ServerCA
		}
		roots, err := loadCA(ca)
		if err != nil {
			return nil, fmt.Errorf("environment %s: %w", name, err)
		}
		u, err := url.Parse(strings.TrimSuffix(ec.HTTPServer, "/"))
		if err != nil {
			return nil, fmt.Errorf("environment %s: %w", name, err)
		}
		host, _, _ := net.SplitHostPort(ec.Server)
		e := &Env{
			Name: name, Server: ec.Server, HTTPServer: u,
			TLS: &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12},
			HTTP: &http.Client{Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
				DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
				TLSHandshakeTimeout: dialTimeout,
				DisableCompression:  true,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     90 * time.Second,
			}},
		}
		if t := ec.Token; t.File != "" {
			e.Tokens = &connect.FileSource{Path: t.File, Field: t.Field, StatusFile: t.StatusFile}
		} else {
			e.Tokens = connect.New(connect.Options{
				Issuer: t.Issuer, ClientID: t.ClientID, Resource: t.Resource, Scope: t.Scope,
				CallbackPort: o.CallbackPort, OpenBrowser: o.OpenBrowser, Store: o.Store, StoreKey: connect.KeychainKey(name, t),
			}, o.Log)
		}
		envs = append(envs, e)
	}
	return envs, nil
}

func loadCA(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return pool, nil
}

// Listener is one local native and/or HTTP address; with Env set, a database without a known
// "<env>/" prefix, the empty one included, is in Env.
type Listener struct {
	Native, HTTP, Env string
}

// Listeners are the top-level pair (native, http) followed by the config's bound listeners. A bound
// listener on the same address as the top-level one replaces it there. Every address must be loopback.
func Listeners(f *connect.File, native, http string) ([]Listener, error) {
	top := Listener{Native: native, HTTP: http}
	for _, l := range f.Listeners {
		if l.Listen == top.Native {
			top.Native = ""
		}
		if l.ListenHTTP == top.HTTP {
			top.HTTP = ""
		}
	}
	var out []Listener
	if top.Native != "" || top.HTTP != "" {
		out = append(out, top)
	}
	for _, l := range f.Listeners {
		out = append(out, Listener{Native: l.Listen, HTTP: l.ListenHTTP, Env: l.Env})
	}
	var errs []error
	for _, l := range out {
		for _, addr := range []string{l.Native, l.HTTP} {
			if addr != "" && !loopback(addr) {
				errs = append(errs, fmt.Errorf("%s is not a loopback address; the connector serves this machine only", addr))
			}
		}
	}
	return out, errors.Join(errs...)
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Connector serves local clients for a set of environments.
type Connector struct {
	envs  map[string]*Env
	names []string
	log   *slog.Logger
	// HandshakeTimeout bounds reading a native client's Hello; default 30 s.
	HandshakeTimeout time.Duration
}

const (
	dialTimeout      = 15 * time.Second
	handshakeTimeout = 30 * time.Second
	// tokenTimeout leaves room for a browser login on the first connection.
	tokenTimeout = 6 * time.Minute
	maxHello     = 64 << 10
)

func New(envs []*Env, log *slog.Logger) *Connector {
	c := &Connector{envs: map[string]*Env{}, log: log, HandshakeTimeout: handshakeTimeout}
	for _, e := range envs {
		c.envs[e.Name] = e
		c.names = append(c.names, e.Name)
	}
	sort.Strings(c.names)
	return c
}

func (c *Connector) Env(name string) (*Env, bool) {
	e, ok := c.envs[name]
	return e, ok
}

// route picks the environment of target on a listener bound to env ("" when unbound).
func (c *Connector) route(target, env string) (*Env, string, error) {
	name, rest, err := connect.SplitTarget(target, env, c.names)
	if err != nil {
		return nil, "", err
	}
	return c.envs[name], rest, nil
}

// Run listens on every listener and serves until ctx ends or a listener fails; open native
// connections are waited for, open HTTP requests get 5 s.
func (c *Connector) Run(ctx context.Context, listeners []Listener) error {
	type server struct {
		ln     net.Listener
		native bool
		env    string
	}
	var servers []server
	defer func() {
		for _, s := range servers {
			s.ln.Close()
		}
	}()
	for _, l := range listeners {
		for _, p := range []struct {
			addr   string
			native bool
		}{{l.Native, true}, {l.HTTP, false}} {
			if p.addr == "" {
				continue
			}
			ln, err := net.Listen("tcp", p.addr)
			if err != nil {
				return err
			}
			servers = append(servers, server{ln, p.native, l.Env})
			c.logReady(ln.Addr().String(), p.native, l.Env)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			if s.native {
				errs <- c.ServeNative(ctx, s.ln, s.env)
			} else {
				errs <- c.ServeHTTP(ctx, s.ln, s.env)
			}
		}()
	}
	var err error
	for range servers {
		if e := <-errs; e != nil && err == nil {
			err = e
		}
		cancel()
	}
	return err
}

func (c *Connector) logReady(addr string, native bool, env string) {
	host, port, _ := net.SplitHostPort(addr)
	db := "<env>/<db>"
	if env != "" {
		db = "<db>"
	}
	attrs := []any{"environments", strings.Join(c.names, ",")}
	if env != "" {
		attrs = []any{"env", env}
	}
	if native {
		c.log.Info("ready", append(attrs, "connect", fmt.Sprintf("clickhouse-client --host %s --port %s -d %s", host, port, db))...)
	} else {
		c.log.Info("ready", append(attrs, "connect", fmt.Sprintf("curl 'http://%s/?database=%s' --data-binary 'SELECT 1'", net.JoinHostPort(host, port), db))...)
	}
}
