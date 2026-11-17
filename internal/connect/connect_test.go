package connect

import (
	"context"
	"encoding/base64"
	"fmt"
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
