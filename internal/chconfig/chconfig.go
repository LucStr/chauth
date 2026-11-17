// Package chconfig loads the YAML configuration of `chauth serve`.
package chconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/LucStr/chauth/internal/config"
	"github.com/LucStr/chauth/internal/rbac"
)

// DefaultDatabase is what an empty target database means, as in ClickHouse itself.
const DefaultDatabase = "default"

type Config struct {
	Listen Listen `json:"listen"`
	// AccessHelp is appended to every "no binding grants it" denial: where to ask for access.
	AccessHelp string      `json:"accessHelp"`
	TLS        config.TLS  `json:"tls"`
	OIDC       config.OIDC `json:"oidc"`
	RBAC       config.RBAC `json:"rbac"`
	Limits     Limits      `json:"limits"`
	Instances  []Instance  `json:"instances"`
}

// Listen addresses; Health serves GET /healthz and /readyz and is off when empty.
type Listen struct {
	Native string `json:"native"`
	HTTP   string `json:"http"`
	Health string `json:"health"`
}

type Limits struct {
	MaxConnectionAge config.Duration `json:"maxConnectionAge"`
	// LeaseDuration is how long one temp user is handed out to new connections or requests.
	LeaseDuration config.Duration `json:"leaseDuration"`
	// TempUserIdleTTL is how long a temp user with no open connection is kept for reuse.
	TempUserIdleTTL           config.Duration `json:"tempUserIdleTTL"`
	SweepInterval             config.Duration `json:"sweepInterval"`
	MaxConnectionsPerUser     int             `json:"maxConnectionsPerUser"`
	MaxConnectionsPerTempUser int             `json:"maxConnectionsPerTempUser"`
	HandshakeTimeout          config.Duration `json:"handshakeTimeout"`
	PreAuthMaxBytes           int             `json:"preAuthMaxBytes"`
}

type Instance struct {
	Name string `json:"name"`
	// Native is host:port of the upstream native TLS port; HTTP is its https:// base URL.
	Native string `json:"native"`
	HTTP   string `json:"http"`
	// TLSMode is verify-full (default) or verify-ca, which skips only the host name check.
	TLSMode       string   `json:"tlsMode"`
	CAFile        string   `json:"caFile"`
	TLSServerName string   `json:"tlsServerName"`
	Databases     []string `json:"databases"`
	// ReadOnlyDatabases are databases where every grant, write and "*" included, yields only the read role.
	ReadOnlyDatabases []string `json:"readOnlyDatabases"`
	// Roles are the upstream roles a grant may name directly.
	Roles []string `json:"roles"`
	// CredentialsFile is a JSON file {"username": ..., "password": ...} for the admin user.
	CredentialsFile string `json:"credentialsFile"`
	TempUserPrefix  string `json:"tempUserPrefix"`
	// TempUserHostIPs are CIDRs put into every temp user's HOST IP; empty leaves hosts open.
	TempUserHostIPs []string `json:"tempUserHostIPs"`
	// RoleTemplate names the upstream role of a database grant; {database} and {level} are replaced.
	RoleTemplate string `json:"roleTemplate"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) ApplyDefaults() {
	setStr := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	setDur := func(v *config.Duration, d time.Duration) {
		if *v == 0 {
			*v = config.Duration(d)
		}
	}
	setInt := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	setStr(&c.Listen.Native, ":9440")
	setStr(&c.Listen.HTTP, ":8443")
	setStr(&c.Listen.Health, ":8080")
	c.OIDC.ApplyDefaults()
	c.RBAC.ApplyDefaults()
	l := &c.Limits
	setDur(&l.MaxConnectionAge, 12*time.Hour)
	setDur(&l.LeaseDuration, time.Duration(l.MaxConnectionAge)/2)
	setDur(&l.TempUserIdleTTL, 5*time.Minute)
	setDur(&l.SweepInterval, time.Minute)
	setDur(&l.HandshakeTimeout, 30*time.Second)
	setInt(&l.MaxConnectionsPerUser, 50)
	setInt(&l.MaxConnectionsPerTempUser, 20)
	setInt(&l.PreAuthMaxBytes, 64<<10)
	for i := range c.Instances {
		in := &c.Instances[i]
		setStr(&in.TLSMode, "verify-full")
		setStr(&in.TempUserPrefix, "chauth_tmp_")
		setStr(&in.RoleTemplate, "chauth_{database}_{level}")
	}
}

var (
	databasePattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	prefixPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	templatePattern = regexp.MustCompile(`^[A-Za-z0-9_{}]+$`)
)

func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	req := func(v, name string) {
		if v == "" {
			add("%s is required", name)
		}
	}
	req(c.TLS.CertFile, "tls.certFile")
	req(c.TLS.KeyFile, "tls.keyFile")
	req(c.OIDC.Issuer, "oidc.issuer")
	req(c.OIDC.Audience, "oidc.audience")
	req(c.RBAC.Dir, "rbac.dir")
	if len(c.OIDC.AllowedClients) == 0 {
		add("oidc.allowedClients must list the clients whose tokens chauth accepts")
	}
	for name, addr := range map[string]string{"listen.native": c.Listen.Native, "listen.http": c.Listen.HTTP} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			add("%s %q must be host:port", name, addr)
		}
	}
	l := c.Limits
	for name, d := range map[string]config.Duration{"maxConnectionAge": l.MaxConnectionAge, "leaseDuration": l.LeaseDuration,
		"tempUserIdleTTL": l.TempUserIdleTTL, "sweepInterval": l.SweepInterval, "handshakeTimeout": l.HandshakeTimeout} {
		if d < 0 {
			add("limits.%s must be positive", name)
		}
	}
	if l.LeaseDuration > l.MaxConnectionAge {
		add("limits.leaseDuration must not exceed limits.maxConnectionAge")
	}
	if l.MaxConnectionsPerUser < 0 || l.MaxConnectionsPerTempUser < 0 {
		add("limits.maxConnectionsPerUser and maxConnectionsPerTempUser must be positive")
	}
	if l.PreAuthMaxBytes < 4<<10 {
		add("limits.preAuthMaxBytes must be at least 4096")
	}
	if len(c.Instances) == 0 {
		add("instances needs at least one entry")
	}
	seen := map[string]bool{}
	for i, in := range c.Instances {
		p := fmt.Sprintf("instances[%d]", i)
		if in.Name == "" || strings.ContainsAny(in.Name, "/.") || seen[in.Name] {
			add("%s.name %q must be unique, non-empty and contain no '/' or '.'", p, in.Name)
		}
		seen[in.Name] = true
		if _, _, err := net.SplitHostPort(in.Native); err != nil {
			add("%s.native %q must be host:port", p, in.Native)
		}
		if u, err := url.Parse(in.HTTP); err != nil || u.Scheme != "https" || u.Host == "" {
			add("%s.http %q must be an https:// URL", p, in.HTTP)
		}
		if in.TLSMode != "verify-full" && in.TLSMode != "verify-ca" {
			add("%s.tlsMode must be verify-full or verify-ca, got %s", p, in.TLSMode)
		}
		req(in.CredentialsFile, p+".credentialsFile")
		if len(in.Databases) == 0 {
			add("%s.databases must list the databases chauth serves", p)
		}
		dbs := map[string]bool{}
		for _, db := range in.Databases {
			if !databasePattern.MatchString(db) || dbs[db] {
				add("%s.databases: %q must be unique letters, digits or '_'", p, db)
			}
			dbs[db] = true
		}
		readOnly := map[string]bool{}
		for _, db := range in.ReadOnlyDatabases {
			if !dbs[db] || readOnly[db] {
				add("%s.readOnlyDatabases: %q must be unique and listed in databases", p, db)
			}
			readOnly[db] = true
		}
		roles := map[string]bool{}
		for _, r := range in.Roles {
			if !rbac.ValidUpstreamRole(r) || roles[r] {
				add("%s.roles: %q must be a unique lowercase role name", p, r)
			}
			roles[r] = true
		}
		if !prefixPattern.MatchString(in.TempUserPrefix) {
			add("%s.tempUserPrefix %q must be lowercase letters, digits or '_', starting with a letter", p, in.TempUserPrefix)
		}
		for _, cidr := range in.TempUserHostIPs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				add("%s.tempUserHostIPs: %q is not a CIDR", p, cidr)
			}
		}
		if !templatePattern.MatchString(in.RoleTemplate) || !strings.Contains(in.RoleTemplate, "{database}") || !strings.Contains(in.RoleTemplate, "{level}") {
			add("%s.roleTemplate %q must contain {database} and {level} and otherwise only letters, digits or '_'", p, in.RoleTemplate)
		}
	}
	return errors.Join(errs...)
}

// Databases maps every instance to its databases, for rbac.
func (c *Config) Databases() rbac.Instances {
	out := make(rbac.Instances, len(c.Instances))
	for _, in := range c.Instances {
		out[in.Name] = in.Databases
	}
	return out
}

// Roles maps every instance to the upstream roles grants may name, for rbac.
func (c *Config) Roles() rbac.Instances {
	out := make(rbac.Instances, len(c.Instances))
	for _, in := range c.Instances {
		out[in.Name] = in.Roles
	}
	return out
}

func (c *Config) Instance(name string) (Instance, bool) {
	for _, in := range c.Instances {
		if in.Name == name {
			return in, true
		}
	}
	return Instance{}, false
}

// Resolve maps a target serve receives, "<instance>/<db>", "<db>" or "", to an instance and a
// database; "" becomes DefaultDatabase and needs an instance prefix when several are configured.
func (c *Config) Resolve(target string) (Instance, string, error) {
	inName, db, qualified := strings.Cut(target, "/")
	if !qualified {
		inName, db = "", target
	}
	if strings.Contains(db, "/") {
		return Instance{}, "", fmt.Errorf("use <db> or <instance>/<db>, got %s", target)
	}
	if qualified {
		in, ok := c.Instance(inName)
		if !ok {
			return Instance{}, "", fmt.Errorf("no instance %s", inName)
		}
		if db == "" {
			db = DefaultDatabase
		}
		return in, db, nil
	}
	if db == "" {
		if len(c.Instances) != 1 {
			return Instance{}, "", errors.New("several instances are configured; use <instance>/<db>")
		}
		return c.Instances[0], DefaultDatabase, nil
	}
	var found []Instance
	for _, in := range c.Instances {
		if slices.Contains(in.Databases, db) {
			found = append(found, in)
		}
	}
	switch len(found) {
	case 1:
		return found[0], db, nil
	case 0:
		return Instance{}, "", fmt.Errorf("serves no database %s", db)
	default:
		names := make([]string, len(found))
		for i, in := range found {
			names[i] = in.Name + "/" + db
		}
		return Instance{}, "", fmt.Errorf("%s is on several instances; use %s", db, strings.Join(names, " or "))
	}
}

// Cap is the level a grant at level reaches on db: at most read on a read-only database.
func (in Instance) Cap(db string, level rbac.Level) rbac.Level {
	if slices.Contains(in.ReadOnlyDatabases, db) {
		return min(level, rbac.Read)
	}
	return level
}

// RoleFor is the upstream role of a database grant at level, after Cap.
func (in Instance) RoleFor(db string, level rbac.Level) string {
	return strings.NewReplacer("{database}", db, "{level}", in.Cap(db, level).String()).Replace(in.RoleTemplate)
}

// CheckReadOnly returns an error for every grant that names a read-only database at write level;
// "*" grants are allowed and capped by Cap.
func (c *Config) CheckReadOnly(res *rbac.Resources) rbac.Errors {
	var errs rbac.Errors
	for _, r := range res.Roles {
		for _, g := range r.Grants {
			in, ok := c.Instance(g.Instance)
			if ok && g.Level == rbac.Write && slices.Contains(in.ReadOnlyDatabases, g.Database) {
				errs = append(errs, rbac.Error{Pos: g.Pos, Msg: fmt.Sprintf("database %s/%s is read-only (instances[].readOnlyDatabases); grant it at level read", g.Instance, g.Database)})
			}
		}
	}
	return errs
}

// UpstreamRoles are the roles a temp user is granted for g: one template role per database at its
// level, plus the named roles; sorted and without duplicates.
func (in Instance) UpstreamRoles(g rbac.Granted) []string {
	out := slices.Clone(g.Roles)
	for db, lv := range g.Databases {
		if lv > rbac.None {
			out = append(out, in.RoleFor(db, lv))
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func (in Instance) Credentials() (config.Credentials, error) {
	return config.ReadCredentials(in.CredentialsFile)
}

// TLSConfig is the client TLS config for an upstream reached at host; tlsServerName overrides host.
func (in Instance) TLSConfig(host string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if in.TLSServerName != "" {
		cfg.ServerName = in.TLSServerName
	}
	if in.CAFile != "" {
		pem, err := os.ReadFile(in.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", in.CAFile)
		}
	}
	if in.TLSMode == "verify-ca" {
		roots := cfg.RootCAs
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("upstream sent no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
			return err
		}
	}
	return cfg, nil
}
