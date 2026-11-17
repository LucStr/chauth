package rbac

import "regexp"

// Kinds of the rules format.
const (
	RoleKind    = "ChRole"
	BindingKind = "ChRoleBinding"
)

var upstreamRolePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidUpstreamRole is the one rule for every upstream role chauth grants, named or from the
// template; ClickHouse compares role names case-sensitively, and SQL still backtick-quotes them.
func ValidUpstreamRole(name string) bool { return upstreamRolePattern.MatchString(name) }
