// Package chapi is the HTTP contract between chauth serve and the connector: the bodies of the
// discovery and access endpoints, and the rule both proxies apply to every forwarded request.
package chapi

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DiscoveryPath answers Discovery without authentication.
	DiscoveryPath = "/.well-known/chauth"
	// AccessPath answers []Access for the Bearer token.
	AccessPath = "/v1/access"
	// TablesPath answers []Table for the database in its db parameter: every table for a token that
	// reaches the whole database, only its declared tables for a token limited to tables.
	TablesPath = "/v1/tables"
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

// DatabaseAccess is one database the token reaches. With Tables, only those tables and verbs.
type DatabaseAccess struct {
	Database string        `json:"database"`
	Level    string        `json:"level"`
	Tables   []TableAccess `json:"tables,omitempty"`
}

type TableAccess struct {
	Table string `json:"table"`
	Verb  string `json:"verb"`
}

// Table is one table of the body of GET TablesPath; Schema is the database.
type Table struct {
	Schema        string `json:"schema"`
	Table         string `json:"table"`
	EstimatedRows uint64 `json:"estimatedRows"`
}

// Error is the body of every non-200 answer of the access and tables endpoints.
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

// IdleTimeout closes a kept-alive client connection that sends no next request.
const IdleTimeout = 2 * time.Minute

// CORSParam makes ClickHouse answer with Access-Control-Allow-Origin; neither proxy forwards it.
const CORSParam = "add_http_cors_header"

// FilterQuery splits raw on '&' and keeps every pair whose decoded key drop rejects, byte-for-byte
// and in order; it returns the decoded values of the dropped pairs whose key equals target in any case.
func FilterQuery(raw, target string, drop func(key string) bool) (string, []string, error) {
	var kept, values []string
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return "", nil, fmt.Errorf("bad query parameter %q", rawKey)
		}
		if strings.EqualFold(key, target) {
			v, err := url.QueryUnescape(rawValue)
			if err != nil {
				return "", nil, fmt.Errorf("bad %s parameter", target)
			}
			values = append(values, v)
			continue
		}
		if !drop(key) {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "&"), values, nil
}

// OneOf reports whether key equals one of names, ignoring case.
func OneOf(key string, names ...string) bool {
	for _, n := range names {
		if strings.EqualFold(key, n) {
			return true
		}
	}
	return false
}

// AppendParam adds key=value to a raw query.
func AppendParam(query, key, value string) string {
	p := url.QueryEscape(key) + "=" + url.QueryEscape(value)
	if query == "" {
		return p
	}
	return query + "&" + p
}

// StripCORS removes every Access-Control-* header: no browser page may read a proxied answer.
func StripCORS(h http.Header) {
	for k := range h {
		if len(k) >= 15 && strings.EqualFold(k[:15], "Access-Control-") {
			delete(h, k)
		}
	}
}
