// Package chtest starts what the ClickHouse-backed tests share: a clickhouse-server container set up
// with examples/clickhouse-setup.sql, a TLS certificate for 127.0.0.1 and localhost, and an OIDC issuer.
package chtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	Image    = "clickhouse/clickhouse-server:26.6"
	Audience = "https://clickhouse.example.test"
	// User and Subject are the token defaults.
	User    = "alice@example.com"
	Subject = "user-1234567890"
	// Client is the default client_id; CLIClient is the other allowed one.
	Client    = "example-agent"
	CLIClient = "example-cli"
	// RootPassword is the container's default user's; the admin's is in examples/clickhouse-setup.sql.
	RootPassword = "Root-secret-1"
	tlsXML       = `<clickhouse>
  <https_port>8443</https_port>
  <tcp_port_secure>9440</tcp_port_secure>
  <openSSL><server>
    <certificateFile>/etc/clickhouse-server/tls/tls.crt</certificateFile>
    <privateKeyFile>/etc/clickhouse-server/tls/tls.key</privateKeyFile>
    <verificationMode>none</verificationMode>
    <loadDefaultCAFile>false</loadDefaultCAFile>
  </server></openSSL>
</clickhouse>`
	// passwordXML mirrors ClickHouse Cloud's default password rules for users created with SQL.
	passwordXML = `<clickhouse>
  <password_complexity>
    <rule><pattern>.{12}</pattern><message>be at least 12 characters long</message></rule>
    <rule><pattern>\p{N}</pattern><message>contain at least 1 numeric character</message></rule>
    <rule><pattern>\p{Ll}</pattern><message>contain at least 1 lowercase character</message></rule>
    <rule><pattern>\p{Lu}</pattern><message>contain at least 1 uppercase character</message></rule>
    <rule><pattern>[^\p{L}\p{N}]</pattern><message>contain at least 1 special character</message></rule>
  </password_complexity>
</clickhouse>`
)

// Env is one started ClickHouse with its certificate, admin credentials and issuer.
type Env struct {
	// PlainHTTP, Native and HTTPS are the upstream ports as host:port.
	PlainHTTP, Native, HTTPS string
	CertFile, KeyFile        string
	CredFile                 string
	Issuer                   *Issuer
	// ClientTLS trusts CertFile for the name localhost.
	ClientTLS *tls.Config
}

// RepoFile is the path of a file relative to the repository root.
func RepoFile(rel string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", rel)
}

// Start runs the container, applies the example setup and the test data, and returns a stop function.
func Start(dir string) (*Env, func(), error) {
	ctx := context.Background()
	e := &Env{Issuer: NewIssuer()}
	stop := func() { e.Issuer.Close() }
	var err error
	if e.CertFile, e.KeyFile, err = WriteCert(dir); err != nil {
		return nil, stop, err
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{Started: true, ContainerRequest: testcontainers.ContainerRequest{
		Image:        Image,
		ExposedPorts: []string{"8123/tcp", "8443/tcp", "9440/tcp"},
		Env:          map[string]string{"CLICKHOUSE_PASSWORD": RootPassword, "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: e.CertFile, ContainerFilePath: "/etc/clickhouse-server/tls/tls.crt", FileMode: 0o644},
			{HostFilePath: e.KeyFile, ContainerFilePath: "/etc/clickhouse-server/tls/tls.key", FileMode: 0o644},
			{Reader: strings.NewReader(tlsXML), ContainerFilePath: "/etc/clickhouse-server/config.d/tls.xml", FileMode: 0o644},
			{Reader: strings.NewReader(passwordXML), ContainerFilePath: "/etc/clickhouse-server/config.d/password.xml", FileMode: 0o644},
		},
		WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(2 * time.Minute),
	}})
	if ctr != nil {
		stop = func() {
			_ = testcontainers.TerminateContainer(ctr)
			e.Issuer.Close()
		}
	}
	if err != nil {
		return nil, stop, fmt.Errorf("start clickhouse: %w", err)
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		return nil, stop, err
	}
	for port, dst := range map[string]*string{"8123/tcp": &e.PlainHTTP, "9440/tcp": &e.Native, "8443/tcp": &e.HTTPS} {
		p, err := ctr.MappedPort(ctx, port)
		if err != nil {
			return nil, stop, err
		}
		*dst = net.JoinHostPort(host, p.Port())
	}
	if err := e.setup(); err != nil {
		return nil, stop, fmt.Errorf("setup: %w", err)
	}
	e.CredFile = filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(e.CredFile, []byte(`{"username":"chauth_admin","password":"Admin-secret-1"}`), 0o600); err != nil {
		return nil, stop, err
	}
	pemCert, _ := os.ReadFile(e.CertFile)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemCert)
	e.ClientTLS = &tls.Config{RootCAs: roots, ServerName: "localhost"}
	return e, stop, nil
}

func (e *Env) setup() error {
	stmts := []string{
		"CREATE DATABASE core", "CREATE DATABASE otel",
		"CREATE TABLE core.items (id UInt32) ENGINE = MergeTree ORDER BY id", "INSERT INTO core.items VALUES (1)",
		"CREATE TABLE otel.spans (id UInt32) ENGINE = MergeTree ORDER BY id", "INSERT INTO otel.spans VALUES (1)",
		"CREATE TABLE core.big (id UInt64) ENGINE = MergeTree ORDER BY id", "INSERT INTO core.big SELECT number FROM numbers(4000000)",
	}
	b, err := os.ReadFile(RepoFile("examples/clickhouse-setup.sql"))
	if err != nil {
		return err
	}
	var sql []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			sql = append(sql, line)
		}
	}
	for _, s := range strings.Split(strings.Join(sql, "\n"), ";") {
		if s = strings.TrimSpace(s); s != "" {
			stmts = append(stmts, s)
		}
	}
	for _, s := range append(stmts, "SYSTEM FLUSH LOGS") {
		if _, err := e.Root(s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

// Root runs stmt as the container's default user over plain HTTP, bypassing chauth.
func (e *Env) Root(stmt string) (string, error) {
	req, _ := http.NewRequest(http.MethodPost, "http://"+e.PlainHTTP+"/", strings.NewReader(stmt))
	req.SetBasicAuth("default", RootPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, body)
	}
	return strings.TrimSpace(string(body)), nil
}

// TempUsers counts the users with the default temp-user prefix.
func (e *Env) TempUsers() (string, error) {
	return e.Root("SELECT count() FROM system.users WHERE startsWith(name, 'chauth_tmp_')")
}

// Claims are a token's contents; the zero value is a read-scoped token for User from Client.
type Claims struct {
	User, Client, Audience, Scope string
	Groups                        []string
	Expired                       bool
	// Alg is RS256 (default) or ES256; Kid overrides the key's own id.
	Alg, Kid string
}

// Issuer is an OIDC issuer with one RSA and one EC signing key.
type Issuer struct {
	srv *httptest.Server
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func NewIssuer() *Issuer {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	is := &Issuer{rsa: rk, ec: ek}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": is.srv.URL, "jwks_uri": is.srv.URL + "/jwks",
			"authorization_endpoint": is.srv.URL + "/authorize", "token_endpoint": is.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256", "ES256"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &ek.PublicKey, KeyID: "ec1", Algorithm: "ES256", Use: "sig"},
			{Key: &rk.PublicKey, KeyID: "rsa1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	is.srv = httptest.NewServer(mux)
	return is
}

func (is *Issuer) URL() string { return is.srv.URL }

func (is *Issuer) Close() { is.srv.Close() }

func (is *Issuer) Token(c Claims) string {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: is.rsa, KeyID: "rsa1"}}
	if c.Alg == "ES256" {
		key = jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: is.ec, KeyID: "ec1"}}
	}
	if c.Kid != "" {
		jwk := key.Key.(jose.JSONWebKey)
		jwk.KeyID = c.Kid
		key.Key = jwk
	}
	signer, err := jose.NewSigner(key, nil)
	if err != nil {
		panic(err)
	}
	set := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	set(&c.Client, Client)
	set(&c.Audience, Audience)
	set(&c.User, User)
	set(&c.Scope, "clickhouse:read")
	exp := time.Now().Add(15 * time.Minute)
	if c.Expired {
		exp = time.Now().Add(-time.Minute)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": is.srv.URL, "sub": Subject, "aud": c.Audience, "client_id": c.Client,
		"exp": exp.Unix(), "iat": time.Now().Add(-time.Hour).Unix(), "email": c.User, "groups": c.Groups, "scope": c.Scope,
	}).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

// WriteCert writes a self-signed certificate for localhost and 127.0.0.1 into dir.
func WriteCert(dir string) (certFile, keyFile string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}
	return certFile, keyFile, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o644)
}
