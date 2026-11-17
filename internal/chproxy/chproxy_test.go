package chproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/LucStr/chauth/internal/chapi"
	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/chtest"
	"github.com/LucStr/chauth/internal/chusers"
	"github.com/LucStr/chauth/internal/chwire"
	"github.com/LucStr/chauth/internal/config"
	"github.com/LucStr/chauth/internal/rbac"
	"github.com/LucStr/chauth/internal/telemetry"
	"github.com/LucStr/chauth/internal/token"
)

var shared *chtest.Env

func TestMain(m *testing.M) {
	os.Exit(func() int {
		dir, err := os.MkdirTemp("", "chauth-test")
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

func mustRoot(t *testing.T, stmt string) string {
	t.Helper()
	out, err := shared.Root(stmt)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type harness struct {
	srv     *Server
	cfg     *chconfig.Config
	native  string
	url     string
	store   *rbac.Store
	audit   *auditLog
	cancel  func()
	stopped chan struct{}
}

func start(t *testing.T, rules string, mutate func(*chconfig.Config)) *harness {
	t.Helper()
	cfg := &chconfig.Config{
		Listen:     chconfig.Listen{Native: "127.0.0.1:9440", HTTP: "127.0.0.1:8443"},
		AccessHelp: "Ask in #data-access.",
		TLS:        config.TLS{CertFile: shared.CertFile, KeyFile: shared.KeyFile},
		OIDC:       config.OIDC{Issuer: shared.Issuer.URL(), Audience: chtest.Audience, AllowedClients: []string{chtest.Client, chtest.CLIClient}},
		RBAC:       config.RBAC{Dir: "unused"},
		Instances: []chconfig.Instance{{
			Name: "main", Native: shared.Native, HTTP: "https://" + shared.HTTPS, CAFile: shared.CertFile, TLSServerName: "localhost",
			Databases: []string{"core", "otel", "system"}, ReadOnlyDatabases: []string{"system"}, Roles: []string{"chauth_querylog_read"}, CredentialsFile: shared.CredFile,
		}},
	}
	if mutate != nil {
		mutate(cfg)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &auditLog{}
	log := telemetry.Logger(audit, nil)
	ctx, cancel := context.WithCancel(context.Background())
	verifier := token.NewVerifier(cfg.OIDC)
	go verifier.Start(ctx, log)
	store := rbac.NewStore(cfg.Databases(), cfg.Roles(), log)
	if err := store.Update([]rbac.File{{Name: "rules.yaml", Data: []byte(rules)}}); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(shared.CertFile, shared.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, verifier, store, &tls.Config{Certificates: []tls.Certificate{cert}}, log)
	if err != nil {
		t.Fatal(err)
	}
	srv.Start(ctx)
	for deadline := time.Now().Add(20 * time.Second); srv.Ready(ctx) != nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not ready: %v", srv.Ready(ctx))
		}
	}
	nativeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	hs := srv.NewHTTPServer()
	h := &harness{srv: srv, cfg: cfg, native: nativeLn.Addr().String(), url: "https://" + httpLn.Addr().String(), store: store, audit: audit, cancel: cancel, stopped: make(chan struct{})}
	go func() { _ = hs.ServeTLS(httpLn, "", "") }()
	go func() {
		defer close(h.stopped)
		_ = srv.ServeNative(ctx, nativeLn)
	}()
	t.Cleanup(func() {
		h.stop()
		_ = hs.Close()
	})
	return h
}

func (h *harness) stop() {
	h.cancel()
	h.srv.Stop()
	<-h.stopped
	h.srv.Close(context.Background())
}

func (h *harness) rules(t *testing.T, rules string) {
	t.Helper()
	if err := h.store.Update([]rbac.File{{Name: "rules.yaml", Data: []byte(rules)}}); err != nil {
		t.Fatal(err)
	}
}

// nativeOpen logs in through chauth's native port; conn, when set, receives the client socket.
func (h *harness) nativeOpen(ctx context.Context, db, tok string, conn *net.Conn) (driver.Conn, error) {
	c, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{h.native}, Auth: clickhouse.Auth{Database: db, Username: "anyone", Password: tok},
		MaxOpenConns: 1, DialTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			c, err := (&tls.Dialer{Config: shared.ClientTLS}).DialContext(ctx, "tcp", addr)
			if conn != nil && err == nil {
				*conn = c
			}
			return c, err
		},
	})
	if err != nil {
		return nil, err
	}
	if err := c.Ping(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func nativeCode(err error) int32 {
	var ex *clickhouse.Exception
	if errors.As(err, &ex) {
		return ex.Code
	}
	return -1
}

// do sends one request through chauth's HTTPS port with the token as Bearer.
func (h *harness) do(t *testing.T, rawQuery string, header http.Header, tok, body string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.url+"/?"+rawQuery, strings.NewReader(body))
	for k, vs := range header {
		req.Header[k] = vs
	}
	if tok != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b)), resp.Header
}

func httpClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: shared.ClientTLS}}
}

func chRole(name string, grants ...string) string {
	return fmt.Sprintf("---\napiVersion: chauth.dev/v1alpha1\nkind: ChRole\nmetadata: {name: %s}\nspec:\n  grants: [%s]\n", name, strings.Join(grants, ", "))
}

func binding(name, role string, subjects ...string) string {
	return fmt.Sprintf("---\napiVersion: chauth.dev/v1alpha1\nkind: ChRoleBinding\nmetadata: {name: %s}\nspec:\n  roleRef: {kind: ChRole, name: %s}\n  subjects: [%s]\n",
		name, role, strings.Join(subjects, ", "))
}

func user(name string) string  { return "{kind: User, name: '" + name + "'}" }
func group(name string) string { return "{kind: Group, name: " + name + "}" }

var (
	coreRead  = binding("core", "main.core.read", user(chtest.User))
	coreWrite = binding("core", "main.core.write", user(chtest.User))
	queryLog  = chRole("ql", "{instance: main, role: chauth_querylog_read, level: read}") + binding("ql", "ql", user(chtest.User))
	allRead   = chRole("all", `{instance: main, database: "*", level: read}`) + binding("all", "all", group("analysts"))
)

func TestRoleMatrix(t *testing.T) {
	h := start(t, coreRead, nil)
	tests := []struct {
		name   string
		claims chtest.Claims
		rules  string
		db     string
		stmt   string
		// wantCode is the native exception code of a refused login, 0 when the login works;
		// wantStatus the HTTP status of the same request.
		wantCode   int32
		wantStatus int
		wantStmt   bool
	}{
		{"read binding reads", chtest.Claims{}, coreRead, "core", "SELECT count() FROM core.items", 0, 200, true},
		{"qualified target", chtest.Claims{}, coreRead, "main/core", "SELECT count() FROM items", 0, 200, true},
		{"read binding does not reach another database", chtest.Claims{}, coreRead, "core", "SELECT count() FROM otel.spans", 0, 500, false},
		{"login to an ungranted database", chtest.Claims{}, coreRead, "otel", "", 497, 403, false},
		{"read level cannot insert", chtest.Claims{Scope: "clickhouse:write"}, coreRead, "core", "INSERT INTO core.items VALUES (2)", 0, 500, false},
		{"write level inserts", chtest.Claims{Scope: "clickhouse:write"}, coreWrite, "core", "INSERT INTO core.items VALUES (3)", 0, 200, true},
		{"read scope caps write binding", chtest.Claims{}, coreWrite, "core", "INSERT INTO core.items VALUES (4)", 0, 500, false},
		{"named role on default database", chtest.Claims{}, queryLog, "", "SELECT count() FROM system.query_log", 0, 200, true},
		{"named role on explicit default", chtest.Claims{}, queryLog, "default", "SELECT count() FROM system.query_log", 0, 200, true},
		{"qualified explicit default", chtest.Claims{}, queryLog, "main/default", "SELECT currentDatabase() = 'default'", 0, 200, true},
		{"named role gives no database", chtest.Claims{}, queryLog, "core", "", 497, 403, false},
		{"database star reads every database", chtest.Claims{User: "bo@example.com", Groups: []string{"analysts"}}, allRead, "otel", "SELECT count() FROM otel.spans", 0, 200, true},
		{"no binding", chtest.Claims{User: "bo@example.com"}, coreRead, "core", "", 497, 403, false},
		{"no clickhouse scope", chtest.Claims{Scope: "openid"}, coreRead, "core", "", 497, 403, false},
		{"client outside the allowlist", chtest.Claims{Client: "other-app"}, coreRead, "core", "", 497, 401, false},
		{"chauth-cli client", chtest.Claims{Client: chtest.CLIClient}, coreRead, "core", "SELECT 1", 0, 200, true},
		{"expired token", chtest.Claims{Expired: true}, coreRead, "core", "", 497, 401, false},
		{"other audience", chtest.Claims{Audience: "https://api.example.test"}, coreRead, "core", "", 497, 401, false},
		{"database not served", chtest.Claims{}, coreRead, "nope", "", 81, 400, false},
		{"unknown instance", chtest.Claims{}, coreRead, "other/core", "", 81, 400, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.rules(t, tt.rules)
			tok := shared.Issuer.Token(tt.claims)
			ctx := context.Background()
			t.Run("native", func(t *testing.T) {
				c, err := h.nativeOpen(ctx, tt.db, tok, nil)
				if tt.wantCode != 0 {
					if code := nativeCode(err); code != tt.wantCode {
						t.Fatalf("login error %v (code %d), want code %d", err, code, tt.wantCode)
					}
					return
				}
				if err != nil {
					t.Fatalf("login: %v", err)
				}
				defer c.Close()
				if err := c.Exec(ctx, tt.stmt); (err == nil) != tt.wantStmt {
					t.Fatalf("%s: error %v, want success %v", tt.stmt, err, tt.wantStmt)
				}
			})
			t.Run("http", func(t *testing.T) {
				status, body, _ := h.do(t, "database="+tt.db, nil, tok, tt.stmt)
				if tt.stmt == "" && tt.wantStatus == 200 {
					return
				}
				if status != tt.wantStatus && !(tt.wantStatus == 500 && status >= 400 && status != 401 && status != 403) {
					t.Fatalf("status %d (%s), want %d", status, body, tt.wantStatus)
				}
			})
		})
	}
}

// TestAudit checks the log line of an allowed and a refused login on both protocols.
func TestAudit(t *testing.T) {
	h := start(t, coreRead, nil)
	tok := shared.Issuer.Token(chtest.Claims{})
	ctx := context.Background()
	c, err := h.nativeOpen(ctx, "core", tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitFor(t, "disconnect line", func() bool { return len(h.audit.all("disconnect")) == 1 })
	h.do(t, "database=core", nil, tok, "SELECT 1")
	h.do(t, "database=otel", nil, tok, "SELECT 1")
	end := h.audit.all("disconnect")[0]
	if end["reason"] != "client closed" || end["db"] != "core" || end["user"] != chtest.User || end["bytes_in"].(float64) <= 0 ||
		end["bytes_out"].(float64) <= 0 || end["duration_ms"] == nil || !strings.HasPrefix(end["temp_user"].(string), "chauth_tmp_") {
		t.Errorf("disconnect line %v", end)
	}
	lines := h.audit.all("connect")
	if len(lines) != 3 {
		t.Fatalf("%d connect lines, want 3: %v", len(lines), lines)
	}
	for i, want := range []map[string]any{
		{"protocol": "native", "decision": "allow", "db": "core", "instance": "main", "level": "read", "scope_cap": "read"},
		{"protocol": "http", "decision": "allow", "db": "core", "status": float64(200)},
		{"protocol": "http", "decision": "deny", "db": "otel", "status": float64(403), "temp_user": ""},
	} {
		for k, v := range want {
			if lines[i][k] != v {
				t.Errorf("line %d: %s = %v, want %v", i, k, lines[i][k], v)
			}
		}
		if lines[i]["user"] != chtest.User || lines[i]["sub"] != "user-1234567890" || lines[i]["client_id"] != chtest.Client {
			t.Errorf("line %d: identity fields %v", i, lines[i])
		}
	}
	if u, _ := lines[0]["temp_user"].(string); !strings.HasPrefix(u, "chauth_tmp_user1234_") {
		t.Errorf("temp_user = %q", u)
	}
	if roles, _ := lines[0]["roles"].([]any); len(roles) != 1 || roles[0] != "chauth_core_read" {
		t.Errorf("roles = %v", lines[0]["roles"])
	}
	for _, l := range lines {
		if b, _ := json.Marshal(l); bytes.Contains(b, []byte(tok[:40])) {
			t.Error("token in the audit log")
		}
	}
}

func TestHostileEmail(t *testing.T) {
	h := start(t, binding("any", "main.core.read", group("staff")), nil)
	ctx := context.Background()
	tests := []struct {
		email string
		ok    bool
	}{
		{"o'brien@example.com", true},
		{`back\slash@example.com`, true},
		{`x\'; DROP USER default; --@example.com`, true},
		{"x'; DROP USER default; --@example.com", true},
		{"new\nline@example.com", false},
		{"nul\x00@example.com", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.email), func(t *testing.T) {
			tok := shared.Issuer.Token(chtest.Claims{User: tt.email, Groups: []string{"staff"}})
			c, err := h.nativeOpen(ctx, "core", tok, nil)
			if !tt.ok {
				if code := nativeCode(err); code != 497 {
					t.Fatalf("login error %v, want code 497", err)
				}
				if status, _, _ := h.do(t, "database=core", nil, tok, "SELECT 1"); status != 403 {
					t.Fatalf("http status %d, want 403", status)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var got string
			if err := c.QueryRow(ctx, "SELECT getSetting('log_comment')").Scan(&got); err != nil || got != tt.email {
				t.Fatalf("native log_comment = %q, %v", got, err)
			}
			status, body, _ := h.do(t, "database=core", nil, tok, "SELECT getSetting('log_comment') FORMAT JSONEachRow")
			var row map[string]string
			_ = json.Unmarshal([]byte(body), &row)
			if status != 200 || row["getSetting('log_comment')"] != tt.email {
				t.Fatalf("http log_comment: %d %s", status, body)
			}
		})
	}
	if n := mustRoot(t, "SELECT count() FROM system.users WHERE name = 'default'"); n != "1" {
		t.Fatal("user default is gone")
	}
}

func TestLogComment(t *testing.T) {
	h := start(t, coreWrite, nil)
	tok := shared.Issuer.Token(chtest.Claims{Scope: "clickhouse:write"})
	ctx := context.Background()
	c, err := h.nativeOpen(ctx, "core", tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id := "lc-" + rand.Text()
	if err := c.Exec(clickhouse.Context(ctx, clickhouse.WithQueryID(id+"-native")), "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if status, body, _ := h.do(t, "database=core&query_id="+id+"-http", nil, tok, "SELECT 1"); status != 200 {
		t.Fatal(status, body)
	}
	overrides := []struct {
		name string
		run  func() error
	}{
		{"native per-query setting", func() error {
			return c.Exec(clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"log_comment": "spoof"})), "SELECT 1")
		}},
		{"native SET", func() error { return c.Exec(ctx, "SET log_comment = 'spoof'") }},
		{"native query SETTINGS", func() error { return c.Exec(ctx, "SELECT 1 SETTINGS log_comment = 'spoof'") }},
		{"http parameter", func() error { return httpErr(h.do(t, "database=core&log_comment=spoof", nil, tok, "SELECT 1")) }},
		{"http query SETTINGS", func() error {
			return httpErr(h.do(t, "database=core", nil, tok, "SELECT 1 SETTINGS log_comment = 'spoof'"))
		}},
	}
	for _, o := range overrides {
		if err := o.run(); err == nil || !strings.Contains(err.Error(), "452") && nativeCode(err) != 452 {
			t.Errorf("%s: error %v, want code 452", o.name, err)
		}
	}
	mustRoot(t, "SYSTEM FLUSH LOGS")
	got := mustRoot(t, fmt.Sprintf("SELECT DISTINCT log_comment FROM system.query_log WHERE query_id IN ('%s-native', '%s-http') AND type = 'QueryFinish'", id, id))
	if got != chtest.User {
		t.Fatalf("query_log log_comment = %q, want %s", got, chtest.User)
	}
}

func httpErr(status int, body string, _ http.Header) error {
	if status == 200 {
		return nil
	}
	return fmt.Errorf("%d: %s", status, body)
}

func TestHTTPCredentialStripping(t *testing.T) {
	h := start(t, coreRead, nil)
	tok := shared.Issuer.Token(chtest.Claims{})
	basic := http.Header{"Authorization": {"Basic " + b64("default:"+tok)}}
	tests := []struct {
		name   string
		query  string
		header http.Header
		status int
	}{
		{"user and password parameters", "user=default&password=root-secret", nil, 200},
		{"upper case parameters", "USER=default&PassWord=root-secret", nil, 200},
		{"escaped parameter name", "%75ser=default&p%61ssword=root-secret", nil, 200},
		{"duplicate user parameters", "user=x&user=default&password=root-secret", nil, 200},
		{"quota_key parameter", "quota_key=q1", nil, 200},
		{"upper case quota_key", "QUOTA_KEY=q2", nil, 200},
		{"X-ClickHouse-User and Key", "", http.Header{"X-Clickhouse-User": {"default"}, "X-Clickhouse-Key": {"root-secret"}}, 200},
		{"lower case headers", "", http.Header{"x-clickhouse-user": {"default"}, "x-clickhouse-key": {"root-secret"}}, 200},
		{"quota header", "", http.Header{"X-Clickhouse-Quota": {"q3"}}, 200},
		{"certificate auth header", "", http.Header{"X-Clickhouse-Ssl-Certificate-Auth": {"on"}}, 200},
		{"token as Basic password", "", basic, 200},
		{"database parameter and header agree", "database=core", http.Header{"X-Clickhouse-Database": {"core"}}, 200},
		{"duplicate database parameters disagree", "database=core&database=otel", nil, 400},
		{"database header alone", "", http.Header{"X-Clickhouse-Database": {"core"}}, 200},
		{"CORS parameter", "add_http_cors_header=1", http.Header{"Origin": {"https://evil.example"}}, 200},
		{"CORS parameter in mixed case", "Add_HTTP_Cors_Header=1", http.Header{"Origin": {"https://evil.example"}}, 200},
	}
	var ids []string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := "strip-" + rand.Text()
			ids = append(ids, "'"+id+"'")
			q := "query_id=" + id
			if tt.query != "" {
				q += "&" + tt.query
			}
			status, body, _ := h.do(t, q, tt.header, tok, "SELECT currentUser(), currentDatabase()")
			if status != tt.status {
				t.Fatalf("status %d (%s), want %d", status, body, tt.status)
			}
			if status == 200 && !strings.HasPrefix(body, "chauth_tmp_") {
				t.Fatalf("ran as %q", body)
			}
		})
	}
	direct, _ := http.NewRequest(http.MethodPost, "http://"+shared.PlainHTTP+"/?add_http_cors_header=1", strings.NewReader("SELECT 1"))
	direct.SetBasicAuth("default", "root-secret")
	direct.Header.Set("Origin", "https://evil.example")
	if resp, err := http.DefaultClient.Do(direct); err != nil || resp.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("ClickHouse itself sent no Access-Control-Allow-Origin (%v); the CORS rows prove nothing", err)
	} else {
		resp.Body.Close()
	}
	mustRoot(t, "SYSTEM FLUSH LOGS")
	if got := mustRoot(t, "SELECT DISTINCT user || ' ' || quota_key FROM system.query_log WHERE type = 'QueryFinish' AND query_id IN ("+strings.Join(ids, ",")+")"); !strings.HasPrefix(got, "chauth_tmp_") || strings.Contains(got, "\n") || strings.TrimSpace(got) != got {
		t.Fatalf("query_log user and quota_key: %q", got)
	}
}

func TestHTTPSession(t *testing.T) {
	h := start(t, coreRead, nil)
	tok := shared.Issuer.Token(chtest.Claims{})
	sid := "s-" + rand.Text()
	if status, body, _ := h.do(t, "session_id="+sid, nil, tok, "SET max_threads = 3"); status != 200 {
		t.Fatal(status, body)
	}
	if status, body, _ := h.do(t, "session_id="+sid, nil, tok, "SELECT getSetting('max_threads')"); status != 200 || body != "3" {
		t.Fatal(status, body)
	}
}

func TestHTTPStreamCut(t *testing.T) {
	h := start(t, coreRead, nil)
	tok := shared.Issuer.Token(chtest.Claims{})
	req, _ := http.NewRequest(http.MethodPost, h.url+"/?max_block_size=1000&max_threads=1",
		strings.NewReader("SELECT id, throwIf(id = 3000000, 'boom') FROM core.big FORMAT TSV"))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || err == nil {
		t.Fatalf("status %d, body error %v: want 200 and a cut body: %.200s", resp.StatusCode, err, b)
	}
	if path, err := exec.LookPath("curl"); err == nil {
		cmd := exec.Command(path, "-sS", "-o", "/dev/null", "--cacert", shared.CertFile, "-H", "Authorization: Bearer "+tok,
			"--data-binary", "SELECT id, throwIf(id = 3000000, 'boom') FROM core.big FORMAT TSV",
			strings.Replace(h.url, "127.0.0.1", "localhost", 1)+"/?max_block_size=1000&max_threads=1")
		cmd.Env = append(os.Environ(), "NO_PROXY=*")
		if err := cmd.Run(); err == nil {
			t.Fatal("curl exited 0 on a cut stream")
		}
	}
}

func TestNativeClientKill(t *testing.T) {
	h := start(t, coreRead, nil)
	tok := shared.Issuer.Token(chtest.Claims{})
	ctx := context.Background()
	var sock net.Conn
	c, err := h.nativeOpen(ctx, "core", tok, &sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id := "kill-" + rand.Text()
	go func() {
		_ = c.Exec(clickhouse.Context(ctx, clickhouse.WithQueryID(id)), "SELECT sleepEachRow(1) FROM numbers(60) SETTINGS max_block_size = 1")
	}()
	running := func() string {
		return mustRoot(t, "SELECT count() FROM system.processes WHERE query_id = '"+id+"'")
	}
	waitFor(t, "query running", func() bool { return running() == "1" })
	sock.Close()
	waitFor(t, "query cancelled", func() bool { return running() == "0" })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !ok(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// TestClickHouseClient runs the real clickhouse-client under a pseudo-terminal: a refused login must
// end the process with chauth's message instead of a password prompt.
func TestClickHouseClient(t *testing.T) {
	bin, err := exec.LookPath("clickhouse-client")
	if err != nil {
		t.Skip("clickhouse-client not on PATH")
	}
	scriptBin, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script not on PATH")
	}
	h := start(t, coreRead, nil)
	_, port, _ := net.SplitHostPort(h.native)
	caFile := filepath.Join(t.TempDir(), "client.xml")
	if err := os.WriteFile(caFile, []byte("<config><openSSL><client><caConfig>"+shared.CertFile+"</caConfig><verificationMode>strict</verificationMode></client></openSSL></config>"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := shared.Issuer.Token(chtest.Claims{})
	tests := []struct {
		name, db, token, query string
		interactive            bool
		wantOut                string
		wantOK                 bool
	}{
		{"query", "core", good, "SELECT count() FROM core.items", false, "", true},
		{"bad token", "core", "not-a-token", "SELECT 1", false, "token rejected", false},
		{"bad token interactive", "core", "not-a-token", "", true, "token rejected", false},
		{"ungranted database interactive", "otel", good, "", true, "no access to main/otel", false},
		{"unknown database", "nope", good, "SELECT 1", false, "serves no database nope", false},
		{"interactive session", "core", good, "", true, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{bin, "--config-file", caFile, "--host", "localhost", "--port", port, "--secure",
				"--user", " JWT AUTHENTICATION ", "--password", tt.token, "-d", tt.db}
			if !tt.interactive {
				args = append(args, "--query", tt.query)
			}
			quoted := make([]string, len(args))
			for i, a := range args {
				quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, scriptBin, "-qec", strings.Join(quoted, " "), "/dev/null")
			cmd.Env = cleanEnv()
			stdin := "exit\n"
			if tt.interactive && tt.wantOK {
				stdin = "SELECT 40 + 2;\n"
			}
			cmd.Stdin = strings.NewReader(stdin)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("clickhouse-client hung: %s", out)
			}
			if (err == nil) != tt.wantOK || !strings.Contains(string(out), tt.wantOut) {
				t.Fatalf("exit %v, output:\n%s", err, out)
			}
			if strings.Contains(strings.ToLower(string(out)), "password for user") {
				t.Fatalf("prompted for a password:\n%s", out)
			}
			if tt.interactive && tt.wantOK && !strings.Contains(string(out), "42") {
				t.Fatalf("interactive query output:\n%s", out)
			}
		})
	}
}

func cleanEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CLICKHOUSE_") {
			out = append(out, kv)
		}
	}
	return append(out, "HOME="+os.TempDir())
}

func TestSigningKeys(t *testing.T) {
	h := start(t, coreRead, nil)
	ctx := context.Background()
	for _, tt := range []struct {
		name string
		c    chtest.Claims
		ok   bool
	}{
		{"RSA key", chtest.Claims{Alg: "RS256"}, true},
		{"EC key", chtest.Claims{Alg: "ES256"}, true},
		{"EC signature under the RSA kid", chtest.Claims{Alg: "ES256", Kid: "rsa1"}, false},
		{"unknown kid", chtest.Claims{Alg: "RS256", Kid: "gone"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tok := shared.Issuer.Token(tt.c)
			c, err := h.nativeOpen(ctx, "core", tok, nil)
			if (err == nil) != tt.ok {
				t.Fatalf("native login error %v, want ok %v", err, tt.ok)
			}
			if c != nil {
				c.Close()
			}
			if status, body, _ := h.do(t, "database=core", nil, tok, "SELECT 1"); (status == 200) != tt.ok {
				t.Fatalf("http %d %s", status, body)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	h := start(t, coreRead, func(c *chconfig.Config) {
		c.Limits.MaxConnectionsPerUser = 1
		c.Limits.MaxConnectionAge = config.Duration(3 * time.Second)
		c.Limits.PreAuthMaxBytes = 8 << 10
	})
	tok := shared.Issuer.Token(chtest.Claims{})
	ctx := context.Background()
	var sock net.Conn
	c, err := h.nativeOpen(ctx, "core", tok, &sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.nativeOpen(ctx, "core", tok, nil); nativeCode(err) != 202 {
		t.Errorf("second native connection: %v, want code 202", err)
	}
	if status, body, _ := h.do(t, "", nil, tok, "SELECT 1"); status != http.StatusTooManyRequests {
		t.Errorf("http while a connection is open: %d %s", status, body)
	}
	_ = sock.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := sock.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read after maxConnectionAge: %v, want EOF", err)
	}
	c.Close()
	waitFor(t, "slot freed", func() bool { s, _, _ := h.do(t, "", nil, tok, "SELECT 1"); return s == 200 })

	if _, err := h.nativeOpen(ctx, "core", strings.Repeat("x", 9<<10), nil); nativeCode(err) != 497 {
		t.Errorf("oversized Hello: %v, want code 497", err)
	}
	if status, _, _ := h.do(t, "", http.Header{"X-Big": {strings.Repeat("x", 16<<10)}}, tok, "SELECT 1"); status != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("oversized headers: %d", status)
	}
}

func TestDiscoveryAndAccess(t *testing.T) {
	h := start(t, coreWrite+queryLog, nil)
	var d chapi.Discovery
	if status := getJSON(t, h.url+"/.well-known/chauth", "", &d); status != 200 {
		t.Fatal(status)
	}
	if d.Native != "localhost:9440" || d.HTTP != "https://localhost:8443" || d.Issuer != shared.Issuer.URL() || d.Audience != chtest.Audience ||
		d.Scopes.Write != "clickhouse:write" || len(d.Instances) != 1 || d.Instances[0].Roles[0] != "chauth_querylog_read" || d.AccessHelp == "" {
		t.Errorf("discovery %+v", d)
	}
	tests := []struct {
		scope string
		want  string
	}{
		{"clickhouse:write", `[{"instance":"main","level":"write","databases":[{"database":"core","level":"write"}],"roles":["chauth_querylog_read"]}]`},
		{"clickhouse:read", `[{"instance":"main","level":"read","databases":[{"database":"core","level":"read"}],"roles":["chauth_querylog_read"]}]`},
		{"openid", `[]`},
	}
	for _, tt := range tests {
		var raw json.RawMessage
		if status := getJSON(t, h.url+"/v1/access", shared.Issuer.Token(chtest.Claims{Scope: tt.scope}), &raw); status != 200 || string(raw) != tt.want {
			t.Errorf("%s: %d %s, want %s", tt.scope, status, raw, tt.want)
		}
	}
	if status := getJSON(t, h.url+"/v1/access", shared.Issuer.Token(chtest.Claims{Client: "other-app"}), nil); status != 401 {
		t.Errorf("unlisted client: %d", status)
	}
}

func getJSON(t *testing.T, url, tok string, v any) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, strings.Replace(url, "127.0.0.1", "localhost", 1), nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if v != nil {
		_ = json.NewDecoder(resp.Body).Decode(v)
	}
	return resp.StatusCode
}

// auditLog keeps the connect and disconnect lines of the server's JSON log.
type auditLog struct {
	mu    sync.Mutex
	lines []map[string]any
}

func (l *auditLog) Write(p []byte) (int, error) {
	var line map[string]any
	if json.Unmarshal(p, &line) == nil && (line["msg"] == "connect" || line["msg"] == "disconnect") {
		l.mu.Lock()
		l.lines = append(l.lines, line)
		l.mu.Unlock()
	}
	return len(p), nil
}

func (l *auditLog) all(msg string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range l.lines {
		if line["msg"] == msg {
			out = append(out, line)
		}
	}
	return out
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestTempUsers(t *testing.T) {
	in := chconfig.Instance{Name: "main", HTTP: "https://" + shared.HTTPS, CAFile: shared.CertFile, TLSServerName: "localhost",
		CredentialsFile: shared.CredFile, TempUserPrefix: "chauth_tmp_", TLSMode: "verify-full"}
	admin, err := chusers.NewAdmin(in)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	opts := chusers.Options{LeaseDuration: 2 * time.Second, MaxConnectionAge: time.Hour, IdleTTL: time.Second, MaxRefs: 2}
	m := chusers.NewManager(admin, in, opts)
	other := chusers.NewManager(admin, in, opts)
	key := chusers.Key{Subject: "sub-1", Email: chtest.User, Level: rbac.Read, Roles: []string{"chauth_core_read"}}
	exists := func(name string) bool {
		return mustRoot(t, "SELECT count() FROM system.users WHERE name = '"+name+"'") == "1"
	}
	acquire := func(k chusers.Key) *chusers.Lease {
		t.Helper()
		l, err := m.Acquire(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}

	a, b, c := acquire(key), acquire(key), acquire(key)
	if a.User != b.User || c.User == a.User {
		t.Errorf("reuse: %s %s %s, want the first two shared and the third new (MaxRefs 2)", a.User, b.User, c.User)
	}
	if !strings.HasPrefix(a.User, "chauth_tmp_sub1"+"") || !exists(a.User) {
		t.Errorf("user %s not created", a.User)
	}
	if got := mustRoot(t, "SHOW CREATE USER "+a.User); !strings.Contains(got, "readonly = 2 CONST") || !strings.Contains(got, "log_comment = \\'"+chtest.User+"\\' CONST") || !strings.Contains(got, "VALID UNTIL") {
		t.Errorf("create statement: %s", got)
	}
	w := acquire(chusers.Key{Subject: "sub-1", Email: chtest.User, Level: rbac.Write, Roles: []string{"chauth_core_write"}})
	if w.User == a.User || strings.Contains(mustRoot(t, "SHOW CREATE USER "+w.User), "readonly") {
		t.Errorf("write lease %s shares or is readonly", w.User)
	}
	if _, err := m.Acquire(ctx, chusers.Key{Subject: "s", Email: "e", Roles: []string{"chauth_secret`"}}); !errors.Is(err, chusers.ErrBadKey) {
		t.Errorf("hostile role name: %v", err)
	}
	if _, err := m.Acquire(ctx, chusers.Key{Subject: "s", Email: "e", Roles: []string{"default_role_without_admin"}}); err == nil {
		t.Error("role the admin may not grant was granted")
	}

	w.Release()
	waitFor(t, "idle user dropped", func() bool { return !exists(w.User) })

	time.Sleep(opts.LeaseDuration)
	d := acquire(key)
	if d.User == a.User || d.User == c.User {
		t.Errorf("lease past its duration was handed out again: %s", d.User)
	}
	a.Release()
	if !exists(a.User) {
		t.Error("user dropped while a connection still uses it")
	}
	b.Release()
	if exists(a.User) {
		t.Error("expired lease not dropped at its last release")
	}

	live, err := other.Acquire(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	expired := "chauth_tmp_gone0000_zzzzzzaaaaaa"
	outside := []string{"outside_expired", "chauth_tmpx_expired", "Chauth_tmp_expired"}
	for _, u := range append(outside, expired) {
		mustRoot(t, "CREATE USER "+u+" IDENTIFIED WITH sha256_password BY 'x' VALID UNTIL '2020-01-01 00:00:00 UTC'")
	}
	defer mustRoot(t, "DROP USER IF EXISTS "+strings.Join(outside, ", "))
	if _, err := m.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if exists(expired) || !exists(live.User) {
		t.Errorf("sweep: expired user exists %v, other process's live user exists %v", exists(expired), exists(live.User))
	}
	mustRoot(t, "SYSTEM FLUSH LOGS")
	for _, u := range outside {
		if !exists(u) || mustRoot(t, "SELECT count() FROM system.query_log WHERE user = 'chauth_admin' AND query LIKE '%"+u+"%'") != "0" {
			t.Errorf("sweep acted on %s, which lacks the prefix", u)
		}
	}
	if err := admin.Exec(ctx, "CREATE USER outside_prefix IDENTIFIED WITH sha256_password BY 'x'"); err == nil {
		t.Error("admin created a user outside the prefix")
	}

	m.Close(ctx)
	other.Close(ctx)
	for _, u := range []string{c.User, d.User, live.User} {
		if exists(u) {
			t.Errorf("%s survived Close", u)
		}
	}
}

// TestRulesChange checks that a changed binding gives the next request a new temp user, and that
// a stopped server drops its users.
func TestRulesChange(t *testing.T) {
	h := start(t, coreRead, nil)
	tok := shared.Issuer.Token(chtest.Claims{})
	_, first, _ := h.do(t, "", nil, tok, "SELECT currentUser()")
	_, again, _ := h.do(t, "", nil, tok, "SELECT currentUser()")
	h.rules(t, coreRead+allRead+binding("all-alice", "all", user(chtest.User)))
	_, changed, _ := h.do(t, "", nil, tok, "SELECT currentUser()")
	if first != again || changed == first || !strings.HasPrefix(changed, "chauth_tmp_") {
		t.Fatalf("users %s %s %s: want the same user until the rules change", first, again, changed)
	}
	h.stop()
	if n := mustRoot(t, "SELECT count() FROM system.users WHERE name IN ('"+first+"', '"+changed+"')"); n != "0" {
		t.Fatalf("%s users left after shutdown", n)
	}
}

// TestReadOnlyDatabase gives write on every database while system is read-only: the temp user gets
// chauth_system_read and no write role there, and /v1/access reports system at read.
func TestReadOnlyDatabase(t *testing.T) {
	h := start(t, chRole("everything", `{instance: main, database: "*", level: write}`)+binding("everything", "everything", user(chtest.User)), nil)
	tok := shared.Issuer.Token(chtest.Claims{Scope: "clickhouse:write"})
	var raw json.RawMessage
	want := `[{"instance":"main","level":"write","databases":[{"database":"core","level":"write"},{"database":"otel","level":"write"},{"database":"system","level":"read"}],"roles":[]}]`
	if status := getJSON(t, h.url+chapi.AccessPath, tok, &raw); status != 200 || string(raw) != want {
		t.Errorf("access: %d %s", status, raw)
	}
	ctx := context.Background()
	c, err := h.nativeOpen(ctx, "system", tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tests := []struct {
		stmt string
		ok   bool
	}{
		{"SELECT count() FROM system.parts WHERE database = 'core'", true},
		{"SELECT count() FROM settings_changes", true},
		{"SELECT count() FROM system.query_log", false},
		{"CREATE TABLE system.chauth_probe (a UInt8) ENGINE = Memory", false},
		{"INSERT INTO core.items VALUES (7)", true},
	}
	for _, tt := range tests {
		if err := c.Exec(ctx, tt.stmt); (err == nil) != tt.ok {
			t.Errorf("native %s: %v, want ok %v", tt.stmt, err, tt.ok)
		}
		if status, body, _ := h.do(t, "database=system", nil, tok, tt.stmt); (status == 200) != tt.ok {
			t.Errorf("http %s: %d %s, want ok %v", tt.stmt, status, body, tt.ok)
		}
	}
	var roles []string
	if err := c.QueryRow(ctx, "SELECT arraySort(currentRoles())").Scan(&roles); err != nil || strings.Join(roles, " ") != "chauth_core_write chauth_otel_write chauth_system_read" {
		t.Errorf("roles %v, %v", roles, err)
	}

	h.rules(t, coreRead)
	readTok := shared.Issuer.Token(chtest.Claims{})
	if status, body, _ := h.do(t, "database=core", nil, readTok, "SELECT count() FROM system.parts"); status == 200 {
		t.Errorf("system.parts without chauth_system_read: %d %s", status, body)
	}
}

// TestHTTPNoReplay: the upstream closes a reused connection after reading the second GET; serve
// must answer 502 instead of sending the GET again.
func TestHTTPNoReplay(t *testing.T) {
	h := start(t, coreRead, nil)
	cert, err := tls.LoadX509KeyPair(shared.CertFile, shared.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	var seen atomic.Int32
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen.Add(1) == 2 {
			conn, _, _ := http.NewResponseController(w).Hijack()
			conn.Close()
			return
		}
		_, _ = io.WriteString(w, "1\n")
	}))
	up.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	up.StartTLS()
	defer up.Close()
	h.srv.instances["main"].httpURL, _ = url.Parse(up.URL)
	front := httptest.NewUnstartedServer(h.srv.Handler())
	front.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	front.StartTLS()
	defer front.Close()
	tok := shared.Issuer.Token(chtest.Claims{})
	var statuses []int
	for range 2 {
		req, _ := http.NewRequest(http.MethodGet, strings.Replace(front.URL, "127.0.0.1", "localhost", 1)+"/?database=core&query=SELECT+1", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := httpClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		statuses = append(statuses, resp.StatusCode)
	}
	if seen.Load() != 2 || statuses[0] != 200 || statuses[1] != http.StatusBadGateway {
		t.Fatalf("upstream saw %d requests, statuses %v; want 2 and [200 502]", seen.Load(), statuses)
	}
}

// TestSetupSQLInReadme keeps the README's upstream setup identical to the file the tests run.
func TestSetupSQLInReadme(t *testing.T) {
	sql, err := os.ReadFile(chtest.RepoFile("examples/clickhouse-setup.sql"))
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(chtest.RepoFile("README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readme, sql) {
		t.Error("README.md does not contain examples/clickhouse-setup.sql verbatim")
	}
}

// TestMixedCaseDatabase serves a database whose template role has upper-case letters: every
// statement chauth sends for it must run, with the role and user quoted.
func TestMixedCaseDatabase(t *testing.T) {
	for _, stmt := range []string{"CREATE DATABASE Mixed", "CREATE TABLE Mixed.t (a UInt8) ENGINE = Memory", "INSERT INTO Mixed.t VALUES (1)",
		"CREATE ROLE chauth_Mixed_read", "GRANT SELECT ON Mixed.* TO chauth_Mixed_read", "GRANT chauth_Mixed_read TO chauth_admin WITH ADMIN OPTION"} {
		mustRoot(t, stmt)
	}
	t.Cleanup(func() {
		mustRoot(t, "DROP ROLE IF EXISTS chauth_Mixed_read")
		mustRoot(t, "DROP DATABASE IF EXISTS Mixed")
	})
	h := start(t, binding("mixed", "main.Mixed.read", user(chtest.User)), func(c *chconfig.Config) {
		c.Instances[0].Databases = append(c.Instances[0].Databases, "Mixed")
	})
	tok := shared.Issuer.Token(chtest.Claims{})
	ctx := context.Background()
	c, err := h.nativeOpen(ctx, "Mixed", tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	var n uint64
	if err := c.QueryRow(ctx, "SELECT count() FROM t").Scan(&n); err != nil || n != 1 {
		t.Fatalf("native: %d %v", n, err)
	}
	c.Close()
	if status, body, _ := h.do(t, "database=Mixed", nil, tok, "SELECT count() FROM t"); status != 200 || body != "1" {
		t.Fatalf("http: %d %s", status, body)
	}
	h.stop()
	tmp, _ := h.audit.all("connect")[0]["temp_user"].(string)
	mustRoot(t, "SYSTEM FLUSH LOGS")
	got := mustRoot(t, "SELECT arrayStringConcat(groupArray(toString(type) || ' ' || replaceRegexpOne(query, 'BY .* VALID', 'BY ? VALID')), '\\n') FROM system.query_log "+
		"WHERE user = 'chauth_admin' AND query LIKE '%"+tmp+"%' AND type != 'QueryStart'")
	for _, want := range []string{"QueryFinish GRANT `chauth_Mixed_read` TO `chauth_tmp_", "QueryFinish CREATE USER chauth_tmp_", "QueryFinish DROP USER IF EXISTS `chauth_tmp_"} {
		if !strings.Contains(got, want) {
			t.Errorf("query_log lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Exception") {
		t.Errorf("a statement failed:\n%s", got)
	}
}

// TestHTTPClientGone: a client that disconnects mid-query cancels the upstream query, also when a
// compressed answer has written nothing yet, so ClickHouse cannot notice the closed connection.
func TestHTTPClientGone(t *testing.T) {
	h := start(t, coreWrite, nil)
	tests := []struct {
		name, scope, encoding string
	}{
		{"read level, gzip", "clickhouse:read", "gzip"},
		{"write level, gzip", "clickhouse:write", "gzip"},
		{"write level, uncompressed", "clickhouse:write", "identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := "gone-" + rand.Text()
			ctx, cancel := context.WithCancel(context.Background())
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.url+"/?database=core&max_block_size=1&query_id="+id, strings.NewReader("SELECT sleepEachRow(1) FROM numbers(60)"))
			req.Header.Set("Authorization", "Bearer "+shared.Issuer.Token(chtest.Claims{Scope: tt.scope}))
			req.Header.Set("Accept-Encoding", tt.encoding)
			go func() {
				if resp, err := httpClient().Do(req); err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()
			running := func() string { return mustRoot(t, "SELECT count() FROM system.processes WHERE query_id = '"+id+"'") }
			waitFor(t, "query running", func() bool { return running() == "1" })
			cancel()
			waitFor(t, "query cancelled", func() bool { return running() == "0" })
		})
	}
}

// TestPreAuthCap: idle connections before a token use up maxPreAuthConnections, one more is closed
// at once, and a connection whose token verified no longer counts.
func TestPreAuthCap(t *testing.T) {
	h := start(t, coreRead, func(c *chconfig.Config) { c.Limits.MaxPreAuthConnections = 2 })
	tok := shared.Issuer.Token(chtest.Claims{})
	ctx := context.Background()
	idle := func() net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", h.native)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// closedAtOnce reads from c: a refused connection ends, an admitted idle one stays open.
	closedAtOnce := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		return !(errors.As(err, &ne) && ne.Timeout())
	}
	held := func() int {
		h.srv.preAuth.mu.Lock()
		defer h.srv.preAuth.mu.Unlock()
		return h.srv.preAuth.total
	}
	a, b := idle(), idle()
	defer a.Close()
	defer b.Close()
	waitFor(t, "two pre-auth slots taken", func() bool { return held() == 2 })
	over := idle()
	defer over.Close()
	if !closedAtOnce(over) {
		t.Fatal("a connection over the cap was admitted")
	}
	if _, err := h.nativeOpen(ctx, "core", tok, nil); err == nil {
		t.Fatal("a client got in while the cap was full")
	}
	a.Close()
	waitFor(t, "slot freed", func() bool { return held() == 1 })
	c, err := h.nativeOpen(ctx, "core", tok, nil)
	if err != nil {
		t.Fatalf("authenticated client after a slot freed: %v", err)
	}
	defer c.Close()
	if held() != 1 {
		t.Fatalf("%d pre-auth slots held, want 1: the verified connection must not count", held())
	}
	d := idle()
	defer d.Close()
	if closedAtOnce(d) {
		t.Fatal("the verified connection still counts against the cap")
	}
	e := idle()
	defer e.Close()
	if !closedAtOnce(e) {
		t.Fatal("third pre-auth connection admitted")
	}
}

func TestPreAuthPerIP(t *testing.T) {
	p := &preAuth{max: 10, maxPerIP: 1, perIP: map[string]int{}}
	a := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	b := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2}
	other := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1}
	release, ok := p.take(a)
	if _, ok2 := p.take(b); !ok || ok2 {
		t.Fatalf("second connection from one address: first %v second %v", ok, ok2)
	}
	if _, ok := p.take(other); !ok {
		t.Fatal("another address refused")
	}
	release()
	release()
	if _, ok := p.take(b); !ok || p.total != 2 {
		t.Fatalf("after release: ok %v, total %d", ok, p.total)
	}
}

// TestHTTPConnectionCap: with maxHTTPConnections open, the next client waits until one closes.
func TestHTTPConnectionCap(t *testing.T) {
	h := start(t, coreRead, func(c *chconfig.Config) { c.Limits.MaxHTTPConnections = 1 })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := h.srv.NewHTTPServer()
	go func() { _ = hs.ServeTLS(h.srv.LimitHTTP(ln), "", "") }()
	defer hs.Close()
	first, err := tls.Dial("tcp", ln.Addr().String(), shared.ClientTLS)
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	tc := tls.Client(second, shared.ClientTLS)
	_ = second.SetDeadline(time.Now().Add(time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("second connection served while the cap was full")
	}
	first.Close()
	third, err := tls.Dial("tcp", ln.Addr().String(), shared.ClientTLS)
	if err != nil {
		t.Fatalf("after the first closed: %v", err)
	}
	third.Close()
}

// ownUsers counts the users of manager m that still exist upstream.
func ownUsers(t *testing.T, m *chusers.Manager) string {
	return mustRoot(t, "SELECT count() FROM system.users WHERE name LIKE 'chauth\\_tmp\\_%\\_"+m.Nonce()+"%'")
}

func testInstance(hosts ...string) chconfig.Instance {
	return chconfig.Instance{Name: "main", HTTP: "https://" + shared.HTTPS, CAFile: shared.CertFile, TLSServerName: "localhost",
		CredentialsFile: shared.CredFile, TempUserPrefix: "chauth_tmp_", TLSMode: "verify-full", TempUserHostIPs: hosts}
}

// TestTempUserFailures: a user whose host limit excludes chauth, or whose GRANT fails, is not
// handed out and does not stay; a drop that failed is retried by the next sweep.
func TestTempUserFailures(t *testing.T) {
	ctx := context.Background()
	addr := mustRoot(t, "SELECT replaceOne(toString(address), '::ffff:', '') FROM system.processes WHERE query_id = queryID()")
	cidr := addr + "/32"
	if strings.Contains(addr, ":") {
		cidr = addr + "/128"
	}
	key := chusers.Key{Subject: "sub-host", Email: chtest.User, Level: rbac.Read, Roles: []string{"chauth_core_read"}}
	opts := chusers.Options{LeaseDuration: time.Minute, MaxConnectionAge: time.Hour, IdleTTL: time.Minute, ProbeTimeout: time.Second}
	tests := []struct {
		name  string
		hosts []string
		key   chusers.Key
		ok    bool
	}{
		{"HOST IP includes chauth", []string{"192.0.2.0/24", cidr}, key, true},
		{"HOST IP excludes chauth", []string{"192.0.2.0/24"}, key, false},
		{"GRANT of a role the admin may not grant", nil, chusers.Key{Subject: "sub-grant", Email: chtest.User, Level: rbac.Read, Roles: []string{"chauth_core_read", "default_role_without_admin"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := testInstance(tt.hosts...)
			admin, err := chusers.NewAdmin(in)
			if err != nil {
				t.Fatal(err)
			}
			m := chusers.NewManager(admin, in, opts)
			defer m.Close(ctx)
			lease, err := m.Acquire(ctx, tt.key)
			if (err == nil) != tt.ok {
				t.Fatalf("Acquire: %v, want ok %v", err, tt.ok)
			}
			if !tt.ok {
				if n := ownUsers(t, m); n != "0" {
					t.Fatalf("%s users left after the failed Acquire", n)
				}
				return
			}
			defer lease.Release()
			if err := admin.Login(ctx, lease.User, lease.Password); err != nil {
				t.Fatalf("login inside the CIDR: %v", err)
			}
		})
	}
	t.Run("failed drop retried by the sweep", func(t *testing.T) {
		in := testInstance()
		admin, _ := chusers.NewAdmin(in)
		m := chusers.NewManager(admin, in, opts)
		lease, err := m.Acquire(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		lease.Release()
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		m.Close(cancelled)
		if n := ownUsers(t, m); n != "1" {
			t.Fatalf("%s users after a failed drop, want 1", n)
		}
		if _, err := m.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
		if n := ownUsers(t, m); n != "0" {
			t.Fatalf("%s users after the sweep, want 0", n)
		}
	})
}

// TestUpstreamUnreachable: with the data ports gone a client gets 210 or 502; with the whole
// instance gone serve is not ready and refuses with 210 or 503.
func TestUpstreamUnreachable(t *testing.T) {
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	tok := shared.Issuer.Token(chtest.Claims{})
	ctx := context.Background()

	h := start(t, coreRead, nil)
	in := h.srv.instances["main"]
	in.cfg.Native = deadAddr
	in.httpURL, _ = url.Parse("https://" + deadAddr)
	if _, err := h.nativeOpen(ctx, "core", tok, nil); nativeCode(err) != chwire.CodeNetworkError {
		t.Errorf("native with the data port gone: %v, want code 210", err)
	}
	if status, body, _ := h.do(t, "database=core", nil, tok, "SELECT 1"); status != http.StatusBadGateway {
		t.Errorf("http with the data port gone: %d %s, want 502", status, body)
	}

	gone := start(t, coreRead, nil)
	gone.srv.instances["main"].admin, _ = chusers.NewAdmin(chconfig.Instance{HTTP: "https://" + deadAddr, CredentialsFile: shared.CredFile})
	if err := gone.srv.Ready(ctx); err == nil {
		t.Error("ready with the instance gone")
	}
	gone.srv.instances["main"].ready.Store(false)
	if _, err := gone.nativeOpen(ctx, "core", tok, nil); nativeCode(err) != chwire.CodeNetworkError {
		t.Errorf("native with the instance gone: %v, want code 210", err)
	}
	if status, body, _ := gone.do(t, "database=core", nil, tok, "SELECT 1"); status != http.StatusServiceUnavailable {
		t.Errorf("http with the instance gone: %d %s, want 503", status, body)
	}
}

// TestHelloInTwoWrites sends the client Hello in two TCP segments with a pause between them.
func TestHelloInTwoWrites(t *testing.T) {
	h := start(t, coreRead, nil)
	conn, err := tls.Dial("tcp", h.native, shared.ClientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var buf bytes.Buffer
	hello := chwire.Hello{ClientName: "split", Major: 26, Minor: 6, Revision: 54479, Database: "core", User: "x", Password: shared.Issuer.Token(chtest.Claims{})}
	_, _ = hello.WriteTo(&buf)
	b := buf.Bytes()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(b[:len(b)/2]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := conn.Write(b[len(b)/2:]); err != nil {
		t.Fatal(err)
	}
	if typ, err := chwire.PeekServerPacket(bufio.NewReader(conn)); err != nil || typ != chwire.ServerHello {
		t.Fatalf("answer packet %d, %v; want the server Hello", typ, err)
	}
}
