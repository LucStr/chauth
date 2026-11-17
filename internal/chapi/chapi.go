// Package chapi is the HTTP contract between chauth serve and the connector: the bodies of the
// discovery and access endpoints, and the rule both proxies apply to every forwarded request.
package chapi

import (
	"io"
	"net/http"
	"strings"
)

const (
	// DiscoveryPath answers Discovery without authentication.
	DiscoveryPath = "/.well-known/chauth"
	// AccessPath answers []Access for the Bearer token.
	AccessPath = "/v1/access"
)

// Discovery is the body of GET DiscoveryPath.
type Discovery struct {
	// Native and HTTP are the request's host with serve's listen ports.
	Native     string     `json:"native"`
	HTTP       string     `json:"http"`
	Issuer     string     `json:"issuer"`
	Audience   string     `json:"audience"`
	Scopes     Scopes     `json:"scopes"`
	Instances  []Instance `json:"instances"`
	AccessHelp string     `json:"access_help,omitempty"`
}

type Scopes struct {
	Read  string `json:"read"`
	Write string `json:"write"`
}

type Instance struct {
	Name      string   `json:"name"`
	Databases []string `json:"databases"`
	Roles     []string `json:"roles"`
}

// Access is what a token reaches on one instance after the scope cap. Level is the temp user's
// level there: write when any database or named role is reached at write.
type Access struct {
	Instance  string           `json:"instance"`
	Level     string           `json:"level"`
	Databases []DatabaseAccess `json:"databases"`
	Roles     []string         `json:"roles"`
}

type DatabaseAccess struct {
	Database string `json:"database"`
	Level    string `json:"level"`
}

// Error is the body of every non-200 answer of the two endpoints.
type Error struct {
	Error string `json:"error"`
}

// NoReplay keeps http.Transport from sending out again after the upstream closed a reused
// connection: a body without GetBody makes the request non-replayable, even a GET.
func NoReplay(out *http.Request) {
	if out.Body == nil || out.Body == http.NoBody {
		out.Body = io.NopCloser(strings.NewReader(""))
	}
	out.GetBody = nil
}
