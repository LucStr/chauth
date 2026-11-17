// Package config holds the configuration blocks shared by serve's config: TLS, OIDC, RBAC,
// durations and the upstream admin credentials.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Scopes chauth uses when oidc.scopes leaves them unset.
const (
	DefaultReadScope  = "clickhouse:read"
	DefaultWriteScope = "clickhouse:write"
)

type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type RBAC struct {
	// Dir holds the ChRole / ChRoleBinding YAML; it is reread when it changes.
	Dir            string   `json:"dir"`
	ReloadInterval Duration `json:"reloadInterval"`
}

type OIDC struct {
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	UsernameClaim string `json:"usernameClaim"`
	// UsernameCaseInsensitive compares User subjects to the username ignoring case; nil means true.
	UsernameCaseInsensitive *bool  `json:"usernameCaseInsensitive"`
	GroupsClaim             string `json:"groupsClaim"`
	// GroupsPrefix is prepended to every group from the token before bindings are matched.
	GroupsPrefix  string `json:"groupsPrefix"`
	Scopes        Scopes `json:"scopes"`
	ClientIDClaim string `json:"clientIdClaim"`
	// AllowedClients are the clients whose tokens are accepted; serve's config requires at least one.
	AllowedClients []string `json:"allowedClients"`
}

// Scopes are the token scopes that cap access at read or allow write; a token with neither is refused.
type Scopes struct {
	Read  string `json:"read"`
	Write string `json:"write"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Duration accepts Go duration strings such as "12h".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (o *OIDC) ApplyDefaults() {
	if o.ClientIDClaim == "" {
		o.ClientIDClaim = "client_id"
	}
	if o.UsernameClaim == "" {
		o.UsernameClaim = "email"
	}
	if o.GroupsClaim == "" {
		o.GroupsClaim = "groups"
	}
	if o.Scopes.Read == "" {
		o.Scopes.Read = DefaultReadScope
	}
	if o.Scopes.Write == "" {
		o.Scopes.Write = DefaultWriteScope
	}
}

func (o OIDC) FoldUsername() bool {
	return o.UsernameCaseInsensitive == nil || *o.UsernameCaseInsensitive
}

func (r *RBAC) ApplyDefaults() {
	if r.ReloadInterval == 0 {
		r.ReloadInterval = Duration(10 * time.Second)
	}
}

// ReadCredentials reads a JSON file {"username": ..., "password": ...}.
func ReadCredentials(path string) (Credentials, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Username == "" || c.Password == "" {
		return Credentials{}, fmt.Errorf("%s needs username and password", path)
	}
	return c, nil
}
