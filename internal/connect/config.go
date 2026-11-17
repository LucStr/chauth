package connect

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// File is connect.yaml.
type File struct {
	// Listen and ListenHTTP are the local native and HTTP addresses with no default environment.
	Listen       string                `json:"listen,omitempty"`
	ListenHTTP   string                `json:"listenHTTP,omitempty"`
	ServerCA     string                `json:"serverCA,omitempty"`
	CallbackPort *int                  `json:"callbackPort,omitempty"`
	Listeners    []Listener            `json:"listeners,omitempty"`
	Environments map[string]*EnvConfig `json:"environments,omitempty"`
}

// Listener is a local native and/or HTTP address bound to one environment.
type Listener struct {
	Listen     string `json:"listen,omitempty"`
	ListenHTTP string `json:"listenHTTP,omitempty"`
	Env        string `json:"env,omitempty"`
}

type EnvConfig struct {
	// Server is serve's native TLS host:port; HTTPServer its https:// base URL, which also answers its API.
	Server     string      `json:"server"`
	HTTPServer string      `json:"httpServer"`
	ServerCA   string      `json:"serverCA,omitempty"`
	Token      TokenConfig `json:"token"`
}

// TokenConfig is either a browser login or a file; there is no way to run a command (ADR 0004).
type TokenConfig struct {
	Login      string `json:"login,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	ClientID   string `json:"clientId,omitempty"`
	Resource   string `json:"resource,omitempty"`
	Scope      string `json:"scope,omitempty"`
	File       string `json:"file,omitempty"`
	Field      string `json:"field,omitempty"`
	StatusFile string `json:"statusFile,omitempty"`
}

// LoadFile reads connect.yaml; a missing file is an empty config.
func LoadFile(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &f, nil
}

func (f *File) EnvNames() []string {
	names := make([]string, 0, len(f.Environments))
	for n := range f.Environments {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Validate checks that every environment names its native and HTTPS server and one token source,
// and that every listener is bound to an environment and listens on at least one protocol.
func (f *File) Validate() error {
	if len(f.Environments) == 0 {
		return errors.New("no environments; add one under environments: in connect.yaml")
	}
	var errs []error
	for _, name := range f.EnvNames() {
		e := f.Environments[name]
		if name == "" || strings.Contains(name, "/") {
			errs = append(errs, fmt.Errorf("environment %q: name must be non-empty without '/'", name))
		}
		if e == nil {
			errs = append(errs, fmt.Errorf("environment %s is empty", name))
			continue
		}
		if _, _, err := net.SplitHostPort(e.Server); err != nil {
			errs = append(errs, fmt.Errorf("environment %s: server %q must be host:port", name, e.Server))
		}
		if u, err := url.Parse(e.HTTPServer); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("environment %s: httpServer %q must be an https:// URL", name, e.HTTPServer))
		}
		t := e.Token
		switch {
		case t.Login != "" && t.File != "":
			errs = append(errs, fmt.Errorf("environment %s: token has both login and file", name))
		case t.Login == "browser":
			if t.Issuer == "" || t.ClientID == "" {
				errs = append(errs, fmt.Errorf("environment %s: a browser login needs issuer and clientId", name))
			}
		case t.Login != "":
			errs = append(errs, fmt.Errorf("environment %s: token.login must be browser, got %s", name, t.Login))
		case t.File == "":
			errs = append(errs, fmt.Errorf("environment %s: token needs login: browser or a file", name))
		}
	}
	for name, addr := range map[string]string{"listen": f.Listen, "listenHTTP": f.ListenHTTP} {
		if _, _, err := net.SplitHostPort(addr); addr != "" && err != nil {
			errs = append(errs, fmt.Errorf("%s %q must be host:port", name, addr))
		}
	}
	for i, l := range f.Listeners {
		if f.Environments[l.Env] == nil {
			errs = append(errs, fmt.Errorf("listeners[%d]: no environment %q", i, l.Env))
		}
		if l.Listen == "" && l.ListenHTTP == "" {
			errs = append(errs, fmt.Errorf("listeners[%d]: needs listen, listenHTTP or both", i))
		}
		for _, addr := range []string{l.Listen, l.ListenHTTP} {
			if _, _, err := net.SplitHostPort(addr); addr != "" && err != nil {
				errs = append(errs, fmt.Errorf("listeners[%d]: %q must be host:port", i, addr))
			}
		}
	}
	return errors.Join(errs...)
}

// KeychainKey names an environment's refresh token in the OS keychain.
func KeychainKey(name string, t TokenConfig) string {
	return "env/" + name + " " + t.Issuer + " " + t.ClientID
}
