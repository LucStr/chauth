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

// Effective narrows granted, capped by scopeCap, by the token's authorization_details on db. nil
// details is a token without the claim. The rows for db win over "*", and table rows over actions rows.
func Effective(granted, scopeCap Level, details []token.Detail, db string) (Access, error) {
	ceiling := min(granted, scopeCap)
	if details == nil || ceiling == None {
		return Access{Level: ceiling}, nil
	}
	var rows []token.Detail
	for _, id := range []string{db, "*"} {
		for _, d := range details {
			if d.Identifier == id {
				rows = append(rows, d)
			}
		}
		if len(rows) > 0 {
			break
		}
	}
	if len(rows) == 0 {
		return Access{}, fmt.Errorf("authorization_details name no row for database %s", db)
	}
	var out Access
	tables := false
	for _, d := range rows {
		tables = tables || len(d.Tables) > 0
		for _, t := range d.Tables {
			for _, v := range t.Verbs {
				g := TableGrant{Database: db, Table: t.Name, Verb: v}
				if VerbLevel(v) <= ceiling && !slices.Contains(out.Tables, g) {
					out.Tables = append(out.Tables, g)
					out.Level = max(out.Level, VerbLevel(v))
				}
			}
		}
	}
	if tables {
		if len(out.Tables) == 0 {
			return Access{}, fmt.Errorf("authorization_details declare only verbs beyond %s on database %s", ceiling, db)
		}
		slices.SortFunc(out.Tables, func(a, b TableGrant) int {
			return strings.Compare(a.Table+"\x00"+a.Verb, b.Table+"\x00"+b.Verb)
		})
		return out, nil
	}
	for _, d := range rows {
		out.Level = max(out.Level, actionsLevel(d.Actions))
	}
	return Access{Level: min(out.Level, ceiling)}, nil
}

// RoleCap is the cap of named-role grants: scopeCap without the claim, else at most the "*" row's
// level, since a named role is no database and only the catch-all row speaks for it.
func RoleCap(scopeCap Level, details []token.Detail) Level {
	if details == nil {
		return scopeCap
	}
	lv := None
	for _, d := range details {
		if d.Identifier == "*" {
			lv = max(lv, actionsLevel(d.Actions))
		}
	}
	return min(lv, scopeCap)
}
