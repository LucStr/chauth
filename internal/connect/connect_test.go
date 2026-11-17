package connect

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func jwtExpiring(exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig"
}

// TestFileSource walks one source through a token file that appears, expires and is fixed, without
// a restart: each row changes the files, then asks for a token.
func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	tokenPath, statusPath := filepath.Join(dir, "token.json"), filepath.Join(dir, "status")
	fresh, stale := jwtExpiring(time.Now().Add(time.Hour)), jwtExpiring(time.Now().Add(-time.Minute))
	src := &FileSource{Path: tokenPath, Field: "access_token", StatusFile: statusPath}
	raw := &FileSource{Path: filepath.Join(dir, "raw.jwt")}
	tests := []struct {
		name          string
		src           *FileSource
		token, status *string // nil leaves the file as is; "" deletes it
		want, err     string
	}{
		{"missing, no status file", src, ptr(""), ptr(""), "", "token file " + tokenPath + " missing or expired"},
		{"missing, status explains", src, nil, ptr("connect your account in Settings\n"), "", "connect your account in Settings"},
		{"expired", src, ptr(`{"access_token":"` + stale + `"}`), ptr(""), "", "token file " + tokenPath + " missing or expired"},
		{"unparsable", src, ptr(`{"access_token":`), nil, "", "token file " + tokenPath + " missing or expired"},
		{"fixed, read again", src, ptr(`{"access_token":"` + fresh + `"}`), nil, fresh, ""},
		{"raw JWT file", raw, nil, nil, "", "token file " + raw.Path + " missing or expired"},
	}
	for _, tt := range tests {
		for path, content := range map[string]*string{tokenPath: tt.token, statusPath: tt.status} {
			switch {
			case content == nil:
			case *content == "":
				_ = os.Remove(path)
			default:
				if err := os.WriteFile(path, []byte(*content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		got, err := tt.src.Token(context.Background())
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("%s: err = %v, want %q", tt.name, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: token %q, err %v", tt.name, got, err)
		}
	}
	if err := os.WriteFile(raw.Path, []byte(fresh+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := raw.Token(context.Background()); err != nil || got != fresh {
		t.Errorf("raw JWT: %q, %v", got, err)
	}
}

func ptr(s string) *string { return &s }

func TestSplitTarget(t *testing.T) {
	envs := []string{"prod", "test"}
	tests := []struct {
		target, defaultEnv, env, rest, err string
	}{
		{"prod/core", "", "prod", "core", ""},
		{"test/", "", "test", "", ""},
		{"test/main/core", "", "test", "main/core", ""},
		{"core", "", "", "", "use <env>/<db>; environments: prod, test"},
		{"", "", "", "", "use <env>/<db>; environments: prod, test"},
		{"", "prod", "prod", "", ""},
		{"core", "prod", "prod", "core", ""},
		{"test/core", "prod", "test", "core", ""},
		{"main/core", "prod", "prod", "main/core", ""},
	}
	for _, tt := range tests {
		env, rest, err := SplitTarget(tt.target, tt.defaultEnv, envs)
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("%q on %q: err = %v, want %q", tt.target, tt.defaultEnv, err, tt.err)
			}
			continue
		}
		if err != nil || env != tt.env || rest != tt.rest {
			t.Errorf("%q on %q: got %q %q %v, want %q %q", tt.target, tt.defaultEnv, env, rest, err, tt.env, tt.rest)
		}
	}
}

func TestValidate(t *testing.T) {
	env := func() *EnvConfig {
		return &EnvConfig{Server: "ch:9440", HTTPServer: "https://ch:8443", Token: TokenConfig{File: "/t"}}
	}
	tests := []struct {
		name   string
		mutate func(*File)
		err    string
	}{
		{"valid", func(*File) {}, ""},
		{"no environments", func(f *File) { f.Environments = nil }, "no environments"},
		{"env name with a slash", func(f *File) { f.Environments["a/b"] = env() }, `environment "a/b": name must be non-empty without '/'`},
		{"no server", func(f *File) { f.Environments["prod"].Server = "" }, `server "" must be host:port`},
		{"no httpServer", func(f *File) { f.Environments["prod"].HTTPServer = "" }, `httpServer "" must be an https:// URL`},
		{"plain http server", func(f *File) { f.Environments["prod"].HTTPServer = "http://ch:8123" }, "must be an https:// URL"},
		{"login and file", func(f *File) { f.Environments["prod"].Token.Login = "browser" }, "token has both login and file"},
		{"browser login without issuer", func(f *File) { f.Environments["prod"].Token = TokenConfig{Login: "browser"} }, "needs issuer and clientId"},
		{"no token source", func(f *File) { f.Environments["prod"].Token = TokenConfig{} }, "token needs login: browser or a file"},
		{"listener without env", func(f *File) { f.Listeners = []Listener{{Listen: "127.0.0.1:9001"}} }, `no environment ""`},
		{"listener without ports", func(f *File) { f.Listeners = []Listener{{Env: "prod"}} }, "needs listen, listenHTTP or both"},
		{"bad listenHTTP", func(f *File) { f.ListenHTTP = "8123" }, `listenHTTP "8123" must be host:port`},
		{"HTTP-only listener", func(f *File) { f.Listeners = []Listener{{ListenHTTP: "127.0.0.1:8124", Env: "prod"}} }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{Environments: map[string]*EnvConfig{"prod": env()}}
			tt.mutate(f)
			err := f.Validate()
			if tt.err == "" && err != nil || tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)) {
				t.Fatalf("err = %v, want %q", err, tt.err)
			}
		})
	}
	f, err := LoadFile("../../examples/connect.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("example: %v", err)
	}
	dir := t.TempDir()
	for name, content := range map[string]string{"api": "environments: {prod: {server: a:1, httpServer: https://a, api: https://a}}\n", "issuer": "issuer: https://auth\n"} {
		path := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s: err = %v, want an unknown field", name, err)
		}
	}
}

func TestAccessExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name string
		tok  tokenResponse
		want time.Time
	}{
		{"expires_in", tokenResponse{AccessToken: jwtExpiring(now.Add(time.Hour)), ExpiresIn: 300}, now.Add(5 * time.Minute)},
		{"exp claim", tokenResponse{AccessToken: jwtExpiring(now.Add(time.Hour))}, now.Add(time.Hour)},
		{"opaque token", tokenResponse{AccessToken: "opaque"}, now.Add(unknownLifetime)},
		{"JWT without exp", tokenResponse{AccessToken: "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".sig"}, now.Add(unknownLifetime)},
	}
	for _, tt := range tests {
		if got := accessExpiry(&tt.tok, now); !got.Equal(tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

type memStore map[string]string

func (m memStore) Get(k string) (string, error) { return m[k], nil }
func (m memStore) Set(k, v string) error        { m[k] = v; return nil }
func (m memStore) Delete(k string) error        { delete(m, k); return nil }

// TestTokenWithoutLogin: without a stored refresh token only Token opens the browser.
func TestTokenWithoutLogin(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"authorization_endpoint":"http://%s/authorize","token_endpoint":"http://%s/token"}`, r.Host, r.Host)
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("refresh_token") != "good" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, `{"access_token":%q}`, jwtExpiring(time.Now().Add(time.Hour)))
		}
	}))
	defer issuer.Close()
	for _, tt := range []struct {
		name, stored string
		wantErr      error
	}{
		{"no stored login", "", ErrLoginRequired},
		{"refresh refused", "revoked", ErrLoginRequired},
		{"refresh works", "good", nil},
	} {
		opened := 0
		c := New(Options{Issuer: issuer.URL, ClientID: "cli", CallbackPort: 0, Store: memStore{"k": tt.stored}, StoreKey: "k",
			OpenBrowser: func(string) error { opened++; return nil }}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		tok, err := c.TokenWithoutLogin(context.Background())
		if !errors.Is(err, tt.wantErr) || opened != 0 || (err == nil) != (tok != "") {
			t.Errorf("%s: token %q, err %v, browser opened %d times", tt.name, tok, err, opened)
		}
	}
}
