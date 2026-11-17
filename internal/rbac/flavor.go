package rbac

import "regexp"

// Flavor names the resource kinds of the rules format.
type Flavor struct {
	RoleKind    string
	BindingKind string
}

// ClickHouse is the only flavor; the built-in roles are the generated per-database ones.
var ClickHouse = Flavor{
	RoleKind:    "ChRole",
	BindingKind: "ChRoleBinding",
}

var upstreamRolePattern = regexp.MustCompile(`^[a-z0-9_]([-a-z0-9._]*[a-z0-9_])?$`)

// ValidUpstreamRole reports whether name may be granted by name; upstream identifiers are still
// quoted when used in SQL.
func ValidUpstreamRole(name string) bool { return upstreamRolePattern.MatchString(name) }
