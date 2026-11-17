package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/chconnect"
	"github.com/LucStr/chauth/internal/chtest"
	"github.com/LucStr/chauth/internal/connect"
	"github.com/LucStr/chauth/internal/token"
)

var shared *chtest.Env

func TestMain(m *testing.M) {
	os.Exit(func() int {
		flag.Parse()
		if testing.Short() {
			return m.Run()
		}
		dir, err := os.MkdirTemp("", "chauth-e2e")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		e, stop, err := chtest.Start(dir)
		defer stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		shared = e
		return m.Run()
	}())
}

const rules = `apiVersion: chauth.dev/v1alpha1
kind: ChRole
metadata: {name: alice}
spec:
  grants:
    - {instance: main, database: core, level: write}
    - {instance: main, database: system, level: write}
    - {instance: main, role: chauth_querylog_read, level: read}
---
apiVersion: chauth.dev/v1alpha1
kind: ChRoleBinding
metadata: {name: alice}
spec:
  roleRef: {kind: ChRole, name: alice}
  subjects: [{kind: User, name: alice@example.com}]
`

// stack is one serve and one connector, wired as a person's laptop would be.
type stack struct {
	dir                      string
	serveConfig, connectYAML string
	native, http, health     string // serve's listen addresses
	local, localHTTP         string // the connector's unbound ports
	bound, boundHTTP         string // the connector's ports bound to prod
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// newStack writes the serve config, the rules, the token files and connect.yaml: env prod holds a
// write token, test a read token, stale an expired one with a status file, forged a bad signature.
func newStack(t *testing.T) *stack {
	t.Helper()
	if shared == nil {
		t.Skip("needs Docker; skipped with -short")
	}
	s := &stack{dir: t.TempDir()}
	for _, a := range []*string{&s.native, &s.http, &s.health, &s.local, &s.localHTTP, &s.bound, &s.boundHTTP} {
		*a = freeAddr(t)
	}
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(s.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("rbac/rules.yaml", rules)
	s.serveConfig = write("serve.yaml", fmt.Sprintf(`listen: {native: %q, http: %q, health: %q}
accessHelp: Ask the data team.
tls: {certFile: %s, keyFile: %s}
oidc: {issuer: %s, audience: %s, allowedClients: [%s, %s]}
rbac: {dir: %s, reloadInterval: 1s}
instances:
  - name: main
    native: %s
    http: https://%s
    caFile: %s
    tlsServerName: localhost
    databases: [core, otel, system]
    readOnlyDatabases: [system]
    roles: [chauth_querylog_read]
    credentialsFile: %s
`, s.native, s.http, s.health, shared.CertFile, shared.KeyFile, shared.Issuer.URL(), chtest.Audience, chtest.Client, chtest.CLIClient,
		filepath.Join(s.dir, "rbac"), shared.Native, shared.HTTPS, shared.CertFile, shared.CredFile))

	forged := strings.Split(shared.Issuer.Token(chtest.Claims{}), ".")
	forged[2] = base64.RawURLEncoding.EncodeToString([]byte("not the signature"))
	write("prod.json", `{"access_token":"`+shared.Issuer.Token(chtest.Claims{Scope: "clickhouse:write"})+`"}`)
	write("test.json", `{"access_token":"`+shared.Issuer.Token(chtest.Claims{})+`"}`)
	write("stale.json", `{"access_token":"`+shared.Issuer.Token(chtest.Claims{Expired: true})+`"}`)
	write("stale.status", "the token expired; reconnect your account\n")
	write("forged.json", `{"access_token":"`+strings.Join(forged, ".")+`"}`)
	env := func(name string) string {
		return fmt.Sprintf("  %s:\n    server: localhost:%s\n    httpServer: https://localhost:%s\n    token: {file: %s, field: access_token, statusFile: %s}\n",
			name, port(s.native), port(s.http), filepath.Join(s.dir, name+".json"), filepath.Join(s.dir, name+".status"))
	}
	s.connectYAML = write("connect.yaml", fmt.Sprintf("listen: %s\nlistenHTTP: %s\nserverCA: %s\nlisteners:\n  - {listen: %s, listenHTTP: %s, env: prod}\nenvironments:\n%s%s%s%s",
		s.local, s.localHTTP, shared.CertFile, s.bound, s.boundHTTP, env("prod"), env("test"), env("stale"), env("forged")))
	return s
}

// run starts serve and the connector in this process and stops both when the test ends.
func (s *stack) run(t *testing.T) {
	t.Helper()
	cfg, err := chconfig.Load(s.serveConfig)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := rbacStore(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served, connected := make(chan error, 1), make(chan error, 1)
	go func() { served <- runServe(ctx, cfg, token.NewVerifier(cfg.OIDC), store, log) }()
	f, err := loadConnect(s.connectYAML)
	if err != nil {
		t.Fatal(err)
	}
	go func() { connected <- runConnect(ctx, f, s.local, s.localHTTP, defaultCallbackPort, log) }()
	t.Cleanup(func() {
		cancel()
		for _, ch := range []chan error{served, connected} {
			if err := <-ch; err != nil {
				t.Errorf("shutdown: %v", err)
			}
		}
	})
	s.waitReady(t)
}

func (s *stack) waitReady(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		resp, err := http.Get("http://" + s.health + "/readyz")
		ready := err == nil && resp.StatusCode == 200
		if resp != nil {
			resp.Body.Close()
		}
		if ready && dials(s.local) && dials(s.boundHTTP) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve or connect not ready: %v", err)
		}
	}
}

func dials(addr string) bool {
	c, err := net.Dial("tcp", addr)
	if err == nil {
		c.Close()
	}
	return err == nil
}

// nativeExec opens a clickhouse-go connection to a connector port, without TLS or password, and runs stmt.
func nativeExec(addr, db, stmt string) error {
	c, err := clickhouse.Open(&clickhouse.Options{Addr: []string{addr}, Auth: clickhouse.Auth{Database: db}, DialTimeout: 10 * time.Second, MaxOpenConns: 1})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		return err
	}
	return c.Exec(ctx, stmt)
}

func TestEndToEndNative(t *testing.T) {
	s := newStack(t)
	s.run(t)
	tests := []struct {
		name, addr, db, stmt string
		code                 int32 // exception code, 0 for success
		msg                  string
	}{
		{"select", s.local, "prod/core", "SELECT count() FROM items", 0, ""},
		{"qualified instance", s.local, "test/main/core", "SELECT count() FROM items", 0, ""},
		{"bound listener, bare name", s.bound, "core", "SELECT count() FROM items", 0, ""},
		{"bound listener, other env", s.bound, "test/core", "SELECT count() FROM items", 0, ""},
		{"insert at write level", s.local, "prod/core", "INSERT INTO core.items VALUES (11)", 0, ""},
		{"insert refused at read level", s.local, "test/core", "INSERT INTO core.items VALUES (12)", 497, "Not enough privileges"},
		{"read-only database at write level", s.local, "prod/system", "SELECT count() FROM parts WHERE database = 'core'", 0, ""},
		{"no write on the read-only database", s.local, "prod/system", "CREATE TABLE system.e2e (a UInt8) ENGINE = Memory", 497, "Not enough privileges"},
		{"expired token file", s.local, "stale/core", "SELECT 1", 497, "the token expired; reconnect your account"},
		{"forged token", s.local, "forged/core", "SELECT 1", 497, "token rejected"},
		{"unknown env", s.local, "stage/core", "SELECT 1", 81, "use <env>/<db>; environments: forged, prod, stale, test"},
		{"database not served", s.local, "prod/nope", "SELECT 1", 81, "serves no database nope"},
		{"ungranted database", s.local, "prod/otel", "SELECT 1", 497, "no access to main/otel for alice@example.com: no binding grants it. Ask the data team."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := nativeExec(tt.addr, tt.db, tt.stmt)
			var ex *clickhouse.Exception
			switch {
			case tt.code == 0 && err != nil:
				t.Fatalf("clickhouse-go: %v", err)
			case tt.code != 0 && (!errors.As(err, &ex) || ex.Code != tt.code || !strings.Contains(ex.Message, tt.msg)):
				t.Fatalf("clickhouse-go: %v, want code %d with %q", err, tt.code, tt.msg)
			}
		})
	}

	bin, err := exec.LookPath("clickhouse-client")
	if err != nil {
		t.Log("clickhouse-client not on PATH; the real-client half is skipped")
		return
	}
	for _, tt := range tests {
		t.Run("clickhouse-client/"+tt.name, func(t *testing.T) {
			host, p, _ := net.SplitHostPort(tt.addr)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "--host", host, "--port", p, "-d", tt.db, "--query", tt.stmt)
			cmd.Env = clientEnv(t)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			switch {
			case ctx.Err() != nil:
				t.Fatalf("clickhouse-client hung: %s", out)
			case tt.code == 0 && err != nil:
				t.Fatalf("exit %v: %s", err, out)
			case tt.code != 0 && (!errors.As(err, &exit) || exit.ExitCode() != int(tt.code%256) || !strings.Contains(string(out), tt.msg)):
				t.Fatalf("exit %v, want %d with %q:\n%s", err, tt.code%256, tt.msg, out)
			case tt.code != 0 && strings.Count(string(out), tt.msg) > 1:
				t.Fatalf("message printed twice:\n%s", out)
			}
		})
	}
}

// clientEnv is the environment without CLICKHOUSE_* variables, which clickhouse-client would read.
func clientEnv(t *testing.T) []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CLICKHOUSE_") && !strings.HasPrefix(kv, "HOME=") {
			out = append(out, kv)
		}
	}
	return append(out, "HOME="+t.TempDir())
}

func TestEndToEndHTTP(t *testing.T) {
	s := newStack(t)
	s.run(t)
	post := func(base, query string, header http.Header, body string) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodPost, "http://"+base+"/?"+query, strings.NewReader(body))
		for k, v := range header {
			req.Header[k] = v
		}
		return http.DefaultClient.Do(req)
	}
	read := func(t *testing.T, resp *http.Response, err error) (int, string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(b))
	}
	tests := []struct {
		name, base, query string
		header            http.Header
		body              string
		status            int
		want              string
	}{
		{"select", s.localHTTP, "database=prod/core", nil, "SELECT count() > 0 FROM items", 200, "1"},
		{"bound port, bare name", s.boundHTTP, "database=core", nil, "SELECT currentDatabase()", 200, "core"},
		{"database header", s.localHTTP, "", http.Header{"X-Clickhouse-Database": {"test/core"}}, "SELECT currentDatabase()", 200, "core"},
		{"local credentials ignored", s.localHTTP, "database=prod/core&user=default&password=root-secret",
			http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("default:root-secret"))}, "X-Clickhouse-User": {"default"}, "X-Clickhouse-Key": {"root-secret"}},
			"SELECT startsWith(currentUser(), 'chauth_tmp_')", 200, "1"},
		{"read level refuses insert", s.localHTTP, "database=test/core", nil, "INSERT INTO core.items VALUES (13)", 500, "Not enough privileges"},
		{"expired token file", s.localHTTP, "database=stale/core", nil, "SELECT 1", 401, "the token expired; reconnect your account"},
		{"forged token", s.localHTTP, "database=forged/core", nil, "SELECT 1", 401, "token rejected"},
		{"unknown env", s.localHTTP, "database=stage/core", nil, "SELECT 1", 400, "use <env>/<db>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := post(tt.base, tt.query, tt.header, tt.body)
			status, body := read(t, resp, err)
			if status != tt.status || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %q, want %d with %q", status, body, tt.status, tt.want)
			}
		})
	}

	t.Run("streams", func(t *testing.T) {
		resp, err := post(s.localHTTP, "database=prod/core&max_block_size=1000", nil, "SELECT id FROM big FORMAT TSV")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		if _, perr := strconv.Atoi(strings.TrimSpace(line)); resp.StatusCode != 200 || resp.ContentLength != -1 || err != nil || perr != nil {
			t.Fatalf("status %d, length %d, first line %q %v", resp.StatusCode, resp.ContentLength, line, err)
		}
	})
	t.Run("mid-stream error cuts the stream", func(t *testing.T) {
		resp, err := post(s.localHTTP, "database=prod/core&max_block_size=1000&max_threads=1", nil, "SELECT id, throwIf(id = 3000000, 'boom') FROM big FORMAT TSV")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); resp.StatusCode != 200 || err == nil {
			t.Fatalf("status %d, read error %v; want 200 and a cut body", resp.StatusCode, err)
		}
	})
}

func TestEndToEndLs(t *testing.T) {
	s := newStack(t)
	s.run(t)
	f, err := loadConnect(s.connectYAML)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newConnector(f, callbackPortOf(f), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err = c.PrintAccess(context.Background(), &out, &errOut, []string{"prod", "test", "stale"})
	want := `DATABASE     LEVEL
prod/core    write
prod/system  read
test/core    read
test/system  read
INSTANCE     ROLE
prod/main    chauth_querylog_read
test/main    chauth_querylog_read
`
	if out.String() != want || errOut.String() != "stale: the token expired; reconnect your account\n" || err == nil {
		t.Fatalf("out:\n%s\nerr out: %q, err %v", out.String(), errOut.String(), err)
	}
}

// TestSmoke builds the binary, runs chauth serve and chauth connect as processes, runs one query on
// each protocol and stops both with SIGTERM: each exits 0 and no temp user is left.
func TestSmoke(t *testing.T) {
	s := newStack(t)
	bin := filepath.Join(s.dir, "chauth")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	var serveOut, connectOut bytes.Buffer
	start := func(out *bytes.Buffer, args ...string) *exec.Cmd {
		cmd := exec.Command(bin, args...)
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	serveCmd := start(&serveOut, "serve", "--config", s.serveConfig)
	connectCmd := start(&connectOut, "connect", "--config", s.connectYAML)
	stop := func(name string, cmd *exec.Cmd, out *bytes.Buffer) {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s exited with %v:\n%s", name, err, out)
			}
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			t.Errorf("%s did not stop:\n%s", name, out)
		}
	}
	defer func() {
		if serveCmd.ProcessState == nil {
			stop("serve", serveCmd, &serveOut)
		}
	}()
	s.waitReady(t)

	if err := nativeExec(s.local, "prod/core", "INSERT INTO core.items VALUES (21)"); err != nil {
		t.Errorf("native: %v", err)
	}
	resp, err := http.Post("http://"+s.localHTTP+"/?database="+url.QueryEscape("prod/core"), "text/plain", strings.NewReader("SELECT countIf(id = 21) FROM items"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "1" {
		t.Errorf("http: %d %s", resp.StatusCode, body)
	}

	stop("connect", connectCmd, &connectOut)
	stop("serve", serveCmd, &serveOut)
	if n, err := shared.TempUsers(); err != nil || n != "0" {
		t.Errorf("%s temp users left (%v):\n%s", n, err, serveOut.String())
	}
	if !strings.Contains(serveOut.String(), `"msg":"disconnect"`) {
		t.Errorf("serve logged no disconnect line:\n%s", serveOut.String())
	}
}

// TestDefaultCallbackPort pins the browser login redirect to http://127.0.0.1:8250/callback, the
// redirect URI identity providers register for the CLI client.
func TestDefaultCallbackPort(t *testing.T) {
	issuer := chtest.NewIssuer()
	defer issuer.Close()
	f := &connect.File{Environments: map[string]*connect.EnvConfig{"prod": {
		Server: "localhost:9440", HTTPServer: "https://localhost:8443",
		Token: connect.TokenConfig{Login: "browser", Issuer: issuer.URL(), ClientID: chtest.CLIClient},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opened string
	envs, err := chconnect.BuildEnvs(f, chconnect.Options{Store: memStore{}, CallbackPort: callbackPortOf(f), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OpenBrowser: func(u string) error {
			opened = u
			cancel()
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = envs[0].Tokens.Token(ctx)
	u, err := url.Parse(opened)
	if err != nil || u.Query().Get("redirect_uri") != "http://127.0.0.1:8250/callback" {
		t.Fatalf("login URL %q: redirect_uri %q", opened, u.Query().Get("redirect_uri"))
	}
}

type memStore map[string]string

func (m memStore) Get(k string) (string, error) { return m[k], nil }
func (m memStore) Set(k, v string) error        { m[k] = v; return nil }
func (m memStore) Delete(k string) error        { delete(m, k); return nil }
