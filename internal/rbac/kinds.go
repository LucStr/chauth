package rbac

import "regexp"

// Kinds of the rules format.
const (
	RoleKind    = "ChRole"
	BindingKind = "ChRoleBinding"
)

var upstreamRolePattern = regexp.MustCompile(`^[a-z0-9_]([-a-z0-9._]*[a-z0-9_])?$`)

// ValidUpstreamRole reports whether name may be granted by name; upstream identifiers are still
// quoted when used in SQL.
func ValidUpstreamRole(name string) bool { return upstreamRolePattern.MatchString(name) }
