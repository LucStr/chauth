package rbac

import (
	"fmt"
	"slices"
	"strings"

	"github.com/LucStr/chauth/internal/token"
)

// Access is what one token reaches on one database. Tables nil means the whole database at Level;
// otherwise only those tables and verbs, and Level is read or write after the strongest verb.
type Access struct {
	Level  Level
	Tables []TableGrant
}

// TableGrant is one verb (select, insert, update, delete) on one table.
type TableGrant struct {
	Database, Table, Verb string
}

// Privilege is the ClickHouse privilege of g's verb.
func (g TableGrant) Privilege() string {
	return map[string]string{"select": "SELECT", "insert": "INSERT", "update": "ALTER UPDATE", "delete": "ALTER DELETE"}[g.Verb]
}

// VerbLevel is the level a table verb needs: read for select, write for the rest.
func VerbLevel(verb string) Level {
	if verb == "select" {
		return Read
	}
	return Write
}

func actionsLevel(actions []string) Level {
	if slices.Contains(actions, "write") {
		return Write
	}
	if slices.Contains(actions, "read") {
		return Read
	}
	return None
}

// Effective narrows granted, capped by scopeCap, by the token's authorization_details on db; nil
// details is a token without the claim. The consent rows for db win over "*" ones and cap the level;
// table rows for db then limit it to their tables, each verb within that level.
func Effective(granted, scopeCap Level, details []token.Detail, db string) (Access, error) {
	level := min(granted, scopeCap)
	if details == nil || level == None {
		return Access{Level: level}, nil
	}
	consent, exact, star := None, false, false
	for _, d := range details {
		if len(d.Actions) > 0 && d.Identifier == db {
			consent, exact = max(consent, actionsLevel(d.Actions)), true
		}
	}
	for _, d := range details {
		if len(d.Actions) > 0 && d.Identifier == "*" && !exact {
			consent, star = max(consent, actionsLevel(d.Actions)), true
		}
	}
	var tables []TableGrant
	for _, d := range details {
		if d.Identifier != db {
			continue
		}
		for _, t := range d.Tables {
			for _, v := range t.Verbs {
				tables = append(tables, TableGrant{Database: db, Table: t.Name, Verb: v})
			}
		}
	}
	switch {
	case exact || star:
		level = min(level, consent)
	case tables == nil:
		return Access{}, fmt.Errorf("authorization_details name no row for database %s", db)
	}
	if tables == nil {
		return Access{Level: level}, nil
	}
	slices.SortFunc(tables, func(a, b TableGrant) int {
		return strings.Compare(a.Table+"\x00"+a.Verb, b.Table+"\x00"+b.Verb)
	})
	out := Access{Tables: []TableGrant{}}
	for _, t := range slices.Compact(tables) {
		if lv := VerbLevel(t.Verb); lv <= level {
			out.Tables = append(out.Tables, t)
			out.Level = max(out.Level, lv)
		}
	}
	if len(out.Tables) == 0 {
		return Access{}, fmt.Errorf("authorization_details declare only table verbs beyond %s on database %s", level, db)
	}
	return out, nil
}

// RoleCap is the cap of named-role grants: scopeCap without the claim; else the lowest consent row
// when a "*" row exists, and none without one or once any row names tables, since a named role may
// reach any database, a narrowed one included.
func RoleCap(scopeCap Level, details []token.Detail) Level {
	if details == nil {
		return scopeCap
	}
	lv, star := scopeCap, false
	for _, d := range details {
		if len(d.Tables) > 0 {
			return None
		}
		lv = min(lv, actionsLevel(d.Actions))
		star = star || d.Identifier == "*"
	}
	if !star {
		return None
	}
	return lv
}

// RoleGrant is one row of system.grants for an upstream role; empty Database or Table mean any.
type RoleGrant struct {
	Role, Access, Database, Table string
	// Column marks a column-level grant, which never covers a whole table.
	Column, PartialRevoke bool
}

// verbAccess are the access types that hold a verb's privilege, the privilege itself first.
var verbAccess = map[string][]string{
	"select": {"SELECT", "ALL"},
	"insert": {"INSERT", "ALL"},
	"update": {"ALTER UPDATE", "ALTER TABLE", "ALTER", "ALL"},
	"delete": {"ALTER DELETE", "ALTER TABLE", "ALTER", "ALL"},
}

// Covers reports whether role's own grants hold verb on db.table. A partial revoke of it anywhere in
// the database counts as not holding it on every table (system.grants shows a prefix revoke such as
// sec* as table sec), and so do column-level grants and roles granted to role.
func Covers(grants []RoleGrant, role string, g TableGrant) bool {
	access, covered := verbAccess[g.Verb], false
	for _, r := range grants {
		if r.Role != role || !slices.Contains(access, r.Access) || r.Database != "" && r.Database != g.Database {
			continue
		}
		if r.PartialRevoke {
			return false
		}
		covered = covered || r.Table == "" || r.Table == g.Table && !r.Column
	}
	return covered
}

// Upstream is what chauth reads from an instance to bound direct table grants.
type Upstream struct {
	Grants []RoleGrant
	// RowPolicyDatabases have a row policy on some table or on the whole database; a direct grant
	// would bypass a policy aimed at the binding's role, so they get no table intent.
	RowPolicyDatabases []string
}

// Holds reports whether a direct grant of g stays within what role reaches; nil u holds nothing.
func (u *Upstream) Holds(role string, g TableGrant) bool {
	return u != nil && !slices.Contains(u.RowPolicyDatabases, g.Database) && Covers(u.Grants, role, g)
}
