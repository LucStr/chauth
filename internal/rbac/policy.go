package rbac

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Policy is a checked set of roles and bindings, ready to answer access questions.
type Policy struct {
	roles     map[string]*Role
	bindings  []*Binding
	instances Instances
}

// Instances maps each configured instance to the databases served on it, or, as the roles
// allowlist of Compile, to the upstream roles grants may name.
type Instances map[string][]string

var generatedRole = regexp.MustCompile(`\.(read|write)$`)

// Compile adds the built-in roles and checks the resources as a whole: duplicate names, role
// references, and grants against instances and, for named-role grants, against the roles
// allowlist. With nil instances it skips every instance and role check.
func Compile(res *Resources, instances, roles Instances) (*Policy, Errors) {
	var errs Errors
	p := &Policy{roles: map[string]*Role{}}
	for _, r := range builtinRoles(instances) {
		p.roles[r.Name] = r
	}
	for _, r := range res.Roles {
		if prev, ok := p.roles[r.Name]; ok {
			if prev.Builtin {
				errs = append(errs, Error{r.Pos, fmt.Sprintf("%s %s has the name of a built-in role", RoleKind, r.Name)})
			} else {
				errs = append(errs, Error{r.Pos, fmt.Sprintf("duplicate %s %s, first defined at %s", RoleKind, r.Name, prev.Pos)})
			}
			continue
		}
		if r.Name != "" {
			p.roles[r.Name] = r
		}
		if instances == nil {
			continue
		}
		for _, g := range r.Grants {
			dbs, ok := instances[g.Instance]
			switch {
			case g.Instance == "":
			case !ok:
				errs = append(errs, Error{g.Pos, fmt.Sprintf("instance %s is not configured", g.Instance)})
			case g.Role != "":
				if !slices.Contains(roles[g.Instance], g.Role) {
					errs = append(errs, Error{g.Pos, fmt.Sprintf("role %s is not in instance %s's roles allowlist", g.Role, g.Instance)})
				}
			case g.Database != "*" && g.Database != "" && !slices.Contains(dbs, g.Database):
				errs = append(errs, Error{g.Pos, fmt.Sprintf("database %s/%s is not configured", g.Instance, g.Database)})
			}
		}
	}
	seen := map[string]*Binding{}
	for _, b := range res.Bindings {
		if prev, ok := seen[b.Name]; ok && b.Name != "" {
			errs = append(errs, Error{b.Pos, fmt.Sprintf("duplicate %s %s, first defined at %s", BindingKind, b.Name, prev.Pos)})
			continue
		}
		seen[b.Name] = b
		if b.RoleRef != "" && p.roles[b.RoleRef] == nil && (instances != nil || !generatedRole.MatchString(b.RoleRef)) {
			errs = append(errs, Error{b.RoleRefPos, fmt.Sprintf("roleRef %s names no %s", b.RoleRef, RoleKind)})
		}
		p.bindings = append(p.bindings, b)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	p.instances = instances
	return p, nil
}

// builtinRoles are "<instance>.<db>.read" and "<instance>.<db>.write" for every configured database.
func builtinRoles(instances Instances) []*Role {
	var out []*Role
	names := make([]string, 0, len(instances))
	for name := range instances {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, inst := range names {
		for _, db := range instances[inst] {
			for _, lv := range []Level{Read, Write} {
				out = append(out, &Role{
					Name:    fmt.Sprintf("%s.%s.%s", inst, db, lv),
					Grants:  []Grant{{Instance: inst, Database: db, Level: lv}},
					Builtin: true,
				})
			}
		}
	}
	return out
}

// ScopeCap is the highest level a token's scopes allow: write, read, or none without either scope.
func ScopeCap(tokenScopes []string, readScope, writeScope string) Level {
	switch {
	case slices.Contains(tokenScopes, writeScope):
		return Write
	case slices.Contains(tokenScopes, readScope):
		return Read
	}
	return None
}

// Who is the holder a binding is matched against.
type Who struct {
	User   string
	Groups []string
	// FoldUser compares User subjects case-insensitively (Unicode simple case folding).
	FoldUser bool
}

// Access returns the highest level any binding of who grants on instance/db, and the names of the
// bindings that grant it.
func (p *Policy) Access(who Who, instance, db string) (Level, []string) {
	level := None
	var matched []string
	for _, b := range p.bindings {
		if !b.matches(who) {
			continue
		}
		role := p.roles[b.RoleRef]
		if role == nil {
			continue
		}
		granted := None
		for _, g := range role.Grants {
			if g.Instance == instance && (g.Database == "*" || g.Database == db) {
				granted = max(granted, g.Level)
			}
		}
		if granted > None {
			matched = append(matched, b.Name)
			level = max(level, granted)
		}
	}
	return level, matched
}

func (b *Binding) matches(who Who) bool {
	for _, s := range b.Subjects {
		switch {
		case s.Kind == "Group" && slices.Contains(who.Groups, s.Name):
			return true
		case s.Kind != "User" || who.User == "":
		case s.Name == who.User, who.FoldUser && strings.EqualFold(s.Name, who.User):
			return true
		}
	}
	return false
}

// Size reports the number of user-defined roles and bindings, for logs.
func (p *Policy) Size() (roles, bindings int) {
	for _, r := range p.roles {
		if !r.Builtin {
			roles++
		}
	}
	return roles, len(p.bindings)
}

// Granted is what one holder reaches on one instance after the scope cap.
type Granted struct {
	// Databases holds each configured database with a level above None.
	Databases map[string]Level
	// Roles are the named upstream roles whose grant level the scope cap reaches, sorted.
	Roles []string
	// Bindings are the bindings that contributed anything, in file order.
	Bindings []string
}

// Grants returns every database level and named role who holds on instance, each capped by
// scopeCap; a named-role grant applies only when scopeCap reaches its level.
func (p *Policy) Grants(who Who, instance string, scopeCap Level) Granted {
	out := Granted{Databases: map[string]Level{}}
	for _, b := range p.bindings {
		role := p.roles[b.RoleRef]
		if role == nil || !b.matches(who) {
			continue
		}
		used := false
		for _, g := range role.Grants {
			if g.Instance != instance {
				continue
			}
			if g.Role != "" {
				if scopeCap >= g.Level && !slices.Contains(out.Roles, g.Role) {
					out.Roles = append(out.Roles, g.Role)
				}
				used = used || scopeCap >= g.Level
				continue
			}
			dbs := []string{g.Database}
			if g.Database == "*" {
				dbs = p.instances[instance]
			}
			for _, db := range dbs {
				if lv := min(g.Level, scopeCap); lv > out.Databases[db] {
					out.Databases[db] = lv
				}
				used = used || min(g.Level, scopeCap) > None
			}
		}
		if used {
			out.Bindings = append(out.Bindings, b.Name)
		}
	}
	sort.Strings(out.Roles)
	return out
}
