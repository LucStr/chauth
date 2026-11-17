package chconnect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LucStr/chauth/internal/chapi"
	"github.com/LucStr/chauth/internal/chwire"
	"github.com/LucStr/chauth/internal/connect"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func jwtExpiring(exp time.Time) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, exp.Unix())) + ".sig"
}

// testEnv points an environment at srv's certificate for both protocols.
func testEnv(name, native string, srv *httptest.Server, tokens connect.TokenSource) *Env {
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	u, _ := url.Parse(srv.URL)
	return &Env{
		Name: name, Server: native, HTTPServer: u, Tokens: tokens,
		TLS:  &tls.Config{ServerName: "127.0.0.1", RootCAs: roots},
		HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableCompression: true}},
	}
}

func TestEnvironmentSelection(t *testing.T) {
	c := New([]*Env{{Name: "prod"}, {Name: "test"}}, quiet)
	tests := []struct {
		target, bound, env, rest, err string
	}{
		{"prod/core", "", "prod", "core", ""},
		{"test/main/core", "", "test", "main/core", ""},
		{"prod/", "", "prod", "", ""},
		{"core", "", "", "", "use <env>/<db>; environments: prod, test"},
		{"", "", "", "", "use <env>/<db>; environments: prod, test"},
		{"stage/core", "", "", "", "use <env>/<db>; environments: prod, test"},
		{"", "prod", "prod", "", ""},
		{"core", "prod", "prod", "core", ""},
		{"main/core", "prod", "prod", "main/core", ""},
		{"test/core", "prod", "test", "core", ""},
		{"stage/core", "prod", "prod", "stage/core", ""},
	}
	for _, tt := range tests {
		e, rest, err := c.route(tt.target, tt.bound)
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("%q on %q: err = %v, want %q", tt.target, tt.bound, err, tt.err)
			}
			continue
		}
		if err != nil || e.Name != tt.env || rest != tt.rest {
			t.Errorf("%q on %q: got %v %q %v, want %s %q", tt.target, tt.bound, e, rest, err, tt.env, tt.rest)
		}
	}

	listeners := []struct {
		name string
		f    connect.File
		want []Listener
		err  string
	}{
		{"top-level only", connect.File{}, []Listener{{Native: "127.0.0.1:9000", HTTP: "127.0.0.1:8123"}}, ""},
		{"bound listener beside the top-level", connect.File{Listeners: []connect.Listener{{Listen: "127.0.0.1:9001", ListenHTTP: "127.0.0.1:8124", Env: "test"}}},
			[]Listener{{Native: "127.0.0.1:9000", HTTP: "127.0.0.1:8123"}, {Native: "127.0.0.1:9001", HTTP: "127.0.0.1:8124", Env: "test"}}, ""},
		{"bound listener takes the top-level ports", connect.File{Listeners: []connect.Listener{{Listen: "127.0.0.1:9000", ListenHTTP: "127.0.0.1:8123", Env: "prod"}}},
			[]Listener{{Native: "127.0.0.1:9000", HTTP: "127.0.0.1:8123", Env: "prod"}}, ""},
		{"bound native only", connect.File{Listeners: []connect.Listener{{Listen: "127.0.0.1:9000", Env: "prod"}}},
			[]Listener{{HTTP: "127.0.0.1:8123"}, {Native: "127.0.0.1:9000", Env: "prod"}}, ""},
		{"non-loopback refused", connect.File{Listeners: []connect.Listener{{Listen: "0.0.0.0:9001", Env: "prod"}}}, nil, "0.0.0.0:9001 is not a loopback address"},
	}
	for _, tt := range listeners {
		got, err := Listeners(&tt.f, "127.0.0.1:9000", "127.0.0.1:8123")
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%s: err = %v, want %q", tt.name, err, tt.err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: got %+v %v, want %+v", tt.name, got, err, tt.want)
		}
	}
}

// fakeNative is a native chauth serve: it reads the Hello and len(want) more bytes, then answers reply.
func fakeNative(t *testing.T, srv *httptest.Server, want, reply string) (string, chan chwire.Hello) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan chwire.Hello, 10)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				h, err := chwire.ReadHello(br, chwire.DefaultMaxHello)
				if err != nil {
					return
				}
				got <- h
				rest := make([]byte, len(want))
				if _, err := io.ReadFull(br, rest); err != nil || string(rest) != want {
					return
				}
				_, _ = conn.Write([]byte(reply))
			}()
		}
	}()
	return ln.Addr().String(), got
}

func serveNative(t *testing.T, c *Connector, env string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = c.ServeNative(ctx, ln, env) }()
	return ln.Addr().String()
}

func TestNative(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	server, hellos := fakeNative(t, srv, "client bytes", "server bytes")
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()

	dir := t.TempDir()
	tokenFile, statusFile := filepath.Join(dir, "token.json"), filepath.Join(dir, "status")
	_ = os.WriteFile(tokenFile, fmt.Appendf(nil, `{"access_token":%q}`, jwtExpiring(time.Now().Add(5*time.Second))), 0o600)
	_ = os.WriteFile(statusFile, []byte("connect your account in Settings\n"), 0o600)
	c := New([]*Env{
		testEnv("prod", server, srv, staticToken("tok-prod")),
		testEnv("test", server, srv, &connect.FileSource{Path: tokenFile, Field: "access_token", StatusFile: statusFile}),
		testEnv("down", deadAddr, srv, staticToken("tok-down")),
	}, quiet)
	unbound, bound := serveNative(t, c, ""), serveNative(t, c, "prod")

	hello := chwire.Hello{ClientName: "ClickHouse client", Major: 26, Minor: 10, Revision: 54479, Password: "typed"}
	tests := []struct {
		name, addr, user, database string
		forwardUser, forwardDB     string
		code                       int32
		msg                        string
	}{
		{"explicit env, user kept", unbound, "alice", "prod/core", "alice", "core", 0, ""},
		{"empty user becomes default", unbound, "", "prod/main/core", "default", "main/core", 0, ""},
		{"jwt marker passes through", unbound, chwire.UserJWT, "prod/", chwire.UserJWT, "", 0, ""},
		{"bound port, no database", bound, "", "", "default", "", 0, ""},
		{"bound port, bare database", bound, "", "core", "default", "core", 0, ""},
		{"unbound port, bare database", unbound, "", "core", "", "", chwire.CodeUnknownDatabase, "chauth connect: use <env>/<db>; environments: down, prod, test"},
		{"interserver marker", unbound, chwire.UserInterserverSecret, "prod/core", "", "", chwire.CodeAccessDenied, "chauth connect: this login method is not accepted; the token is the password"},
		{"ssh marker", bound, chwire.UserSSHKey, "core", "", "", chwire.CodeAccessDenied, "chauth connect: this login method is not accepted; the token is the password"},
		{"token file expires within 10 s", unbound, "", "test/core", "", "", chwire.CodeAccessDenied, "connect your account in Settings"},
		{"server down", unbound, "", "down/core", "", "", chwire.CodeNetworkError, "chauth connect: cannot reach " + deadAddr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", tt.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			h := hello
			h.User, h.Database = tt.user, tt.database
			var buf bytes.Buffer
			_, _ = h.WriteTo(&buf)
			buf.WriteString("client bytes") // same segment as the Hello
			if _, err := conn.Write(buf.Bytes()); err != nil {
				t.Fatal(err)
			}
			br := bufio.NewReader(conn)
			if tt.code != 0 {
				e, err := chwire.ReadException(br, 1<<16)
				if err != nil || e.Code != tt.code || e.Message != tt.msg {
					t.Fatalf("got %+v %v, want %d %q", e, err, tt.code, tt.msg)
				}
				return
			}
			got := <-hellos
			want := chwire.Hello{ClientName: h.ClientName, Major: 26, Minor: 10, Revision: 54479, Database: tt.forwardDB, User: tt.forwardUser, Password: "tok-prod"}
			if got != want {
				t.Fatalf("forwarded %+v, want %+v", got, want)
			}
			if reply, err := io.ReadAll(br); err != nil || string(reply) != "server bytes" {
				t.Fatalf("reply %q, %v", reply, err)
			}
		})
	}
}

func TestHTTP(t *testing.T) {
	type seen struct {
		header http.Header
		query  url.Values
		body   string
	}
	got := make(chan seen, 1)
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- seen{r.Header.Clone(), r.URL.Query(), string(body)}
		w.Header().Set("X-ClickHouse-Summary", `{"read_rows":"1"}`)
		switch r.URL.Path {
		case "/stream":
			_, _ = io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			<-release
			_, _ = io.WriteString(w, "second\n")
		case "/cut":
			_, _ = io.WriteString(w, "partial\n")
			w.(http.Flusher).Flush()
			conn, _, _ := http.NewResponseController(w).Hijack()
			conn.Close()
		default:
			_, _ = io.WriteString(w, "1\n")
		}
	}))
	defer srv.Close()
	c := New([]*Env{testEnv("prod", "", srv, staticToken("tok-prod")), testEnv("test", "", srv, staticToken("tok-test"))}, quiet)
	serve := func(env string) string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { _ = c.ServeHTTP(ctx, ln, env) }()
		return "http://" + ln.Addr().String()
	}
	unbound, bound := serve(""), serve("prod")

	tests := []struct {
		name, base, query string
		header            http.Header
		wantQuery         url.Values
		wantDBHeader      string
		wantBearer        string
		status            int
	}{
		{"param rewritten, credentials removed in any case", unbound, "?database=prod/core&user=a&USER=b&Password=c&password=d&query=SELECT+1",
			http.Header{"Authorization": {"Basic eDp5"}, "X-Clickhouse-User": {"a", "b"}, "X-Clickhouse-Key": {"k"}},
			url.Values{"database": {"core"}, "query": {"SELECT 1"}}, "", "Bearer tok-prod", 200},
		{"header rewritten", unbound, "", http.Header{"X-Clickhouse-Database": {"test/main/core"}, "x-clickhouse-user": {"x"}},
			url.Values{}, "main/core", "Bearer tok-test", 200},
		{"bound, no database at all", bound, "", nil, url.Values{}, "", "Bearer tok-prod", 200},
		{"bound, other env explicitly", bound, "?database=test/core", nil, url.Values{"database": {"core"}}, "", "Bearer tok-test", 200},
		{"unbound, no database", unbound, "", nil, nil, "", "", 400},
		{"database twice", unbound, "?database=prod/core", http.Header{"X-Clickhouse-Database": {"prod/core"}}, nil, "", "", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, tt.base+"/"+tt.query, strings.NewReader("SELECT 1"))
			for k, v := range tt.header {
				req.Header[k] = v
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d %s", resp.StatusCode, body)
			}
			if tt.status != 200 {
				if resp.Header.Get("X-ClickHouse-Exception-Code") != "81" {
					t.Fatalf("exception code %q", resp.Header.Get("X-ClickHouse-Exception-Code"))
				}
				return
			}
			s := <-got
			if !reflect.DeepEqual(s.query, tt.wantQuery) || s.header.Get("X-ClickHouse-Database") != tt.wantDBHeader ||
				!reflect.DeepEqual(s.header.Values("Authorization"), []string{tt.wantBearer}) ||
				s.header.Get("X-ClickHouse-User") != "" || s.header.Get("X-ClickHouse-Key") != "" || s.body != "SELECT 1" {
				t.Fatalf("upstream saw %+v", s)
			}
			if resp.Header.Get("X-ClickHouse-Summary") == "" {
				t.Fatal("response header dropped")
			}
		})
	}

	t.Run("streams without buffering", func(t *testing.T) {
		resp, err := http.Get(unbound + "/stream?database=prod/core")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		<-got
		br := bufio.NewReader(resp.Body)
		if line, err := br.ReadString('\n'); err != nil || line != "first\n" {
			t.Fatalf("first line %q %v", line, err)
		}
		close(release)
		if rest, err := io.ReadAll(br); err != nil || string(rest) != "second\n" {
			t.Fatalf("rest %q %v", rest, err)
		}
	})
	t.Run("mid-body cut reaches the client", func(t *testing.T) {
		resp, err := http.Get(unbound + "/cut?database=prod/core")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		<-got
		body, err := io.ReadAll(resp.Body)
		if err == nil || string(body) != "partial\n" {
			t.Fatalf("body %q, err %v; want the partial body and an error", body, err)
		}
	})
}

func TestPrintAccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/chauth":
			_ = json.NewEncoder(w).Encode(chapi.Discovery{
				Instances:  []chapi.Instance{{Name: "main", Databases: []string{"core", "otel", "audit"}}, {Name: "events", Databases: []string{"clicks", "audit"}}},
				AccessHelp: "Ask in #data\nfor access.",
			})
		case "/v1/access":
			if r.Header.Get("Authorization") == "Bearer empty" {
				_, _ = io.WriteString(w, "[]")
				return
			}
			_ = json.NewEncoder(w).Encode([]chapi.Access{
				{Instance: "main", Level: "write", Roles: []string{"chauth_querylog_read"},
					Databases: []chapi.DatabaseAccess{{Database: "core", Level: "write"}, {Database: "audit", Level: "read"}}},
				{Instance: "events", Level: "read", Roles: []string{}, Databases: []chapi.DatabaseAccess{{Database: "clicks", Level: "read"}}},
			})
		}
	}))
	defer srv.Close()
	missing := &connect.FileSource{Path: filepath.Join(t.TempDir(), "none"), StatusFile: filepath.Join(t.TempDir(), "none")}
	c := New([]*Env{
		testEnv("prod", "", srv, staticToken("full")),
		testEnv("stage", "", srv, staticToken("empty")),
		testEnv("test", "", srv, missing),
	}, quiet)
	var out, errOut bytes.Buffer
	err := c.PrintAccess(context.Background(), &out, &errOut, c.Names())
	want := `DATABASE         LEVEL
prod/core        write
prod/main/audit  read
prod/clicks      read
INSTANCE         ROLE
prod/main        chauth_querylog_read
stage: nothing is reachable with this token. Ask in #data for access.
`
	wantErr := "test: token file " + missing.Path + " missing or expired\n"
	if out.String() != want || errOut.String() != wantErr || err == nil {
		t.Fatalf("out:\n%s\nerr out: %q, err %v", out.String(), errOut.String(), err)
	}
}

// TestClickHouseClient runs the real client against a refusing connector and a fake serve that
// answers the Hello with an Exception: each must end the client with that message, not a password prompt.
func TestClickHouseClient(t *testing.T) {
	bin, err := exec.LookPath("clickhouse-client")
	if err != nil {
		t.Skip("clickhouse-client not on PATH")
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(conn)
			if h, err := chwire.ReadHello(br, chwire.DefaultMaxHello); err == nil {
				_ = chwire.WriteException(conn, chwire.CodeUnknownDatabase, "serve saw database "+h.Database+" as "+h.User)
			}
			conn.Close()
		}
	}()
	missing := &connect.FileSource{Path: filepath.Join(t.TempDir(), "none"), StatusFile: filepath.Join(t.TempDir(), "status")}
	_ = os.WriteFile(missing.StatusFile, []byte("connect your account in Settings"), 0o600)
	c := New([]*Env{testEnv("prod", ln.Addr().String(), srv, staticToken("tok")), testEnv("test", "", srv, missing)}, quiet)
	addr := serveNative(t, c, "")
	host, port, _ := net.SplitHostPort(addr)
	tests := []struct{ database, want string }{
		{"core", "chauth connect: use <env>/<db>; environments: prod, test. (UNKNOWN_DATABASE)"},
		{"test/core", ". connect your account in Settings. (ACCESS_DENIED)"},
		{"prod/core", "serve saw database core as default. (UNKNOWN_DATABASE)"},
	}
	for _, tt := range tests {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, bin, "--host", host, "--port", port, "-d", tt.database, "--query", "SELECT 1")
		cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || !strings.Contains(string(out), tt.want) {
			t.Errorf("%s: err %v, output:\n%s", tt.database, err, out)
		}
	}
}

// TestHTTPNoReplay: chauth serve closes a reused connection after reading the second GET; the
// connector must answer 502 instead of sending the GET again.
func TestHTTPNoReplay(t *testing.T) {
	var seen atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen.Add(1) == 2 {
			conn, _, _ := http.NewResponseController(w).Hijack()
			conn.Close()
			return
		}
		_, _ = io.WriteString(w, "1\n")
	}))
	defer srv.Close()
	c := New([]*Env{testEnv("prod", "", srv, staticToken("tok"))}, quiet)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.ServeHTTP(ctx, ln, "prod") }()
	var statuses []int
	for range 2 {
		resp, err := http.Get("http://" + ln.Addr().String() + "/?query=SELECT+1")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		statuses = append(statuses, resp.StatusCode)
	}
	if seen.Load() != 2 || statuses[0] != 200 || statuses[1] != http.StatusBadGateway {
		t.Fatalf("server saw %d requests, statuses %v; want 2 and [200 502]", seen.Load(), statuses)
	}
}
