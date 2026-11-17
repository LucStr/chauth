package chconfig

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LucStr/chauth/internal/rbac"
)

func TestExampleLoads(t *testing.T) {
	c, err := Load("../../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC.Scopes.Read != "clickhouse:read" || time.Duration(c.Limits.LeaseDuration) != 6*time.Hour || c.Instances[0].RoleFor("core", rbac.Write) != "chauth_core_write" ||
		c.Instances[0].RoleFor("system", rbac.Write) != "chauth_system_read" {
		t.Fatalf("%+v", c)
	}
}

func valid() Config {
	c := Config{}
	c.TLS.CertFile, c.TLS.KeyFile = "c", "k"
	c.OIDC.Issuer, c.OIDC.Audience, c.OIDC.AllowedClients = "https://i", "a", []string{"cli"}
	c.RBAC.Dir = "/rbac"
	c.Instances = []Instance{{Name: "main", Native: "ch:9440", HTTP: "https://ch:8443", Databases: []string{"core", "system"}, CredentialsFile: "f"}}
	return c
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		err    string // substring; "" = valid
	}{
		{"valid with defaults", func(*Config) {}, ""},
		{"no allowed clients", func(c *Config) { c.OIDC.AllowedClients = nil }, "oidc.allowedClients must list"},
		{"lease longer than connection age", func(c *Config) { c.Limits.MaxConnectionAge = 3600e9; c.Limits.LeaseDuration = 7200e9 }, "leaseDuration must not exceed"},
		{"plain http upstream", func(c *Config) { c.Instances[0].HTTP = "http://ch:8123" }, "must be an https:// URL"},
		{"insecure tls mode", func(c *Config) { c.Instances[0].TLSMode = "require" }, "tlsMode must be verify-full or verify-ca"},
		{"database with a quote", func(c *Config) { c.Instances[0].Databases = []string{"co`re"} }, `"co` + "`" + `re" must be unique`},
		{"role name with a space", func(c *Config) { c.Instances[0].Roles = []string{"a b"} }, `roles: "a b"`},
		{"prefix with a wildcard", func(c *Config) { c.Instances[0].TempUserPrefix = "tmp*" }, "tempUserPrefix"},
		{"host that is not a CIDR", func(c *Config) { c.Instances[0].TempUserHostIPs = []string{"10.0.0.1"} }, `"10.0.0.1" is not a CIDR`},
		{"template without level", func(c *Config) { c.Instances[0].RoleTemplate = "ch_{database}" }, "roleTemplate"},
		{"instance name with a dot", func(c *Config) { c.Instances[0].Name = "a.b" }, "contain no '/' or '.'"},
		{"read-only database not served", func(c *Config) { c.Instances[0].ReadOnlyDatabases = []string{"otel"} }, `readOnlyDatabases: "otel" must be unique and listed in databases`},
		{"read-only database twice", func(c *Config) { c.Instances[0].ReadOnlyDatabases = []string{"system", "system"} }, "readOnlyDatabases"},
		{"tiny pre-auth cap", func(c *Config) { c.Limits.PreAuthMaxBytes = 10 }, "preAuthMaxBytes"},
		{"upper-case database", func(c *Config) { c.Instances[0].Databases = []string{"Core"} }, ""},
		{"database starting with a digit", func(c *Config) { c.Instances[0].Databases = []string{"1core"} }, ""},
		{"template role starting with a digit", func(c *Config) {
			c.Instances[0].RoleTemplate = "{database}_{level}"
			c.Instances[0].Databases = []string{"core", "1core"}
		}, `databases: "1core" gives the role "1core_read"`},
		{"named role with a dot", func(c *Config) { c.Instances[0].Roles = []string{"chauth.querylog"} }, `roles: "chauth.querylog"`},
		{"mixed-case named role", func(c *Config) { c.Instances[0].Roles = []string{"Chauth_QueryLog"} }, ""},
		{"negative reload interval", func(c *Config) { c.RBAC.ReloadInterval = -1 }, "rbac.reloadInterval must be positive"},
		{"negative shutdown grace", func(c *Config) { c.Limits.ShutdownGrace = -1 }, "limits.shutdownGrace must be positive"},
		{"negative pre-auth connection cap", func(c *Config) { c.Limits.MaxPreAuthConnectionsPerIP = -1 }, "maxPreAuthConnectionsPerIP must not be negative"},
		{"negative HTTP connection cap", func(c *Config) { c.Limits.MaxHTTPConnections = -1 }, "maxHTTPConnections must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(&c)
			c.ApplyDefaults()
			err := c.Validate()
			if tt.err == "" && err != nil || tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)) {
				t.Fatalf("err = %v, want %q", err, tt.err)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	one := valid()
	two := valid()
	two.Instances = append(two.Instances, Instance{Name: "logs", Databases: []string{"core", "otel"}})
	tests := []struct {
		cfg          Config
		target       string
		instance, db string
		err          string
	}{
		{one, "", "main", "default", ""},
		{one, "default", "main", "default", ""},
		{one, "main/default", "main", "default", ""},
		{two, "default", "", "", "several instances are configured"},
		{two, "logs/default", "logs", "default", ""},
		{one, "core", "main", "core", ""},
		{one, "main/system", "main", "system", ""},
		{one, "main/", "main", "default", ""},
		{one, "missing", "", "", "serves no database missing"},
		{one, "other/core", "", "", "no instance other"},
		{one, "main/a/b", "", "", "use <db> or <instance>/<db>"},
		{two, "", "", "", "several instances are configured"},
		{two, "otel", "logs", "otel", ""},
		{two, "core", "", "", "core is on several instances; use main/core or logs/core"},
	}
	for _, tt := range tests {
		in, db, err := tt.cfg.Resolve(tt.target)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%q: err = %v, want %q", tt.target, err, tt.err)
			}
			continue
		}
		if err != nil || in.Name != tt.instance || db != tt.db {
			t.Errorf("%q: got %s %s %v, want %s %s", tt.target, in.Name, db, err, tt.instance, tt.db)
		}
	}
}

func TestUpstreamRoles(t *testing.T) {
	c := valid()
	c.Instances[0].ReadOnlyDatabases = []string{"system"}
	c.ApplyDefaults()
	in := c.Instances[0]
	tests := []struct {
		name    string
		granted rbac.Granted
		want    []string
	}{
		{"levels, named roles, duplicates", rbac.Granted{
			Databases: map[string]rbac.Level{"system": rbac.Read, "core": rbac.Write, "gone": rbac.None},
			Roles:     []string{"chauth_querylog_read", "chauth_core_write"},
		}, []string{"chauth_core_write", "chauth_querylog_read", "chauth_system_read"}},
		{"write on a read-only database gives only its read role", rbac.Granted{
			Databases: map[string]rbac.Level{"system": rbac.Write, "core": rbac.Write},
		}, []string{"chauth_core_write", "chauth_system_read"}},
		{"read stays read", rbac.Granted{Databases: map[string]rbac.Level{"system": rbac.Read}}, []string{"chauth_system_read"}},
	}
	for _, tt := range tests {
		if got := in.UpstreamRoles(tt.granted); !slices.Equal(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCheckReadOnly(t *testing.T) {
	c := valid()
	c.Instances[0].ReadOnlyDatabases = []string{"system"}
	tests := []struct {
		name  string
		grant string
		err   string
	}{
		{"explicit write on a read-only database", "{instance: main, database: system, level: write}", "a.yaml:4: database main/system is read-only (instances[].readOnlyDatabases); grant it at level read"},
		{"read on a read-only database", "{instance: main, database: system, level: read}", ""},
		{"write on every database is capped, not refused", `{instance: main, database: "*", level: write}`, ""},
		{"write on a writable database", "{instance: main, database: core, level: write}", ""},
		{"unknown instance is left to rbac", "{instance: logs, database: system, level: write}", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := "apiVersion: chauth.dev/v1alpha1\nkind: ChRole\nmetadata: {name: x}\nspec: {grants: [" + tt.grant + "]}\n"
			res, errs := rbac.Parse([]rbac.File{{Name: "a.yaml", Data: []byte(yaml)}})
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			errs = c.CheckReadOnly(res)
			if tt.err == "" && len(errs) > 0 || tt.err != "" && (len(errs) != 1 || errs[0].Error() != tt.err) {
				t.Fatalf("errors = %v, want %q", errs, tt.err)
			}
		})
	}
}

func TestUpstreamTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		in   Instance
		ok   bool
	}{
		{"verify-full, matching name", Instance{TLSMode: "verify-full", CAFile: ca, TLSServerName: "example.com"}, true},
		{"verify-full, wrong name", Instance{TLSMode: "verify-full", CAFile: ca, TLSServerName: "wrong.test"}, false},
		{"verify-full, untrusted CA", Instance{TLSMode: "verify-full", TLSServerName: "example.com"}, false},
		{"verify-ca, wrong name", Instance{TLSMode: "verify-ca", CAFile: ca, TLSServerName: "wrong.test"}, true},
		{"verify-ca, untrusted CA", Instance{TLSMode: "verify-ca", TLSServerName: "example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := tt.in.TLSConfig("127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), cfg)
			if err == nil {
				conn.Close()
			}
			if (err == nil) != tt.ok {
				t.Fatalf("handshake err = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestLoadRejectsZeroReloadInterval(t *testing.T) {
	b, err := os.ReadFile("../../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"0s", "-5s"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(strings.Replace(string(b), "reloadInterval: 10s", "reloadInterval: "+v, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "rbac.reloadInterval must be positive") {
			t.Errorf("reloadInterval %s: err = %v", v, err)
		}
	}
}
