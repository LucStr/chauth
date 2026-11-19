package rbac

import (
	"reflect"
	"strings"
	"testing"

	"github.com/LucStr/chauth/internal/token"
)

func TestEffective(t *testing.T) {
	row := func(id string, actions ...string) token.Detail {
		return token.Detail{Type: "clickhouse", Identifier: id, Actions: actions}
	}
	tables := func(id string, rules ...token.TableRule) token.Detail {
		return token.Detail{Type: "clickhouse", Identifier: id, Tables: rules}
	}
	tbl := func(name string, verbs ...string) token.TableRule { return token.TableRule{Name: name, Verbs: verbs} }
	tg := func(table, verb string) TableGrant { return TableGrant{Database: "core", Table: table, Verb: verb} }
	tests := []struct {
		name         string
		granted, cap Level
		details      []token.Detail
		want         Access
		err          string
		roleCap      Level
	}{
		{"no claim: bindings capped by scope", Write, Read, nil, Access{Level: Read}, "", Read},
		{"no claim, no binding", None, Write, nil, Access{}, "", Write},
		{"empty claim denies", Write, Write, []token.Detail{}, Access{}, "no row", None},
		{"star read", Write, Write, []token.Detail{row("*", "read")}, Access{Level: Read}, "", Read},
		{"table rows elsewhere drop named roles", Write, Write, []token.Detail{row("*", "write"), tables("otel", tbl("spans", "select"))}, Access{Level: Write}, "", None},
		{"db override beats star", Write, Write, []token.Detail{row("*", "read"), row("core", "write")}, Access{Level: Write}, "", Read},
		{"override narrows below star", Write, Write, []token.Detail{row("*", "write"), row("core", "read")}, Access{Level: Read}, "", Read},
		{"write never exceeds bindings", Read, Write, []token.Detail{row("core", "read", "write")}, Access{Level: Read}, "", None},
		{"write never exceeds scope", Write, Read, []token.Detail{row("*", "write")}, Access{Level: Read}, "", Read},
		{"unmatched db denied", Write, Write, []token.Detail{row("otel", "write")}, Access{}, "no row", None},
		{"tables within db consent", Write, Write,
			[]token.Detail{row("core", "write"), tables("core", tbl("items", "insert", "select"))},
			Access{Level: Write, Tables: []TableGrant{tg("items", "insert"), tg("items", "select")}}, "", None},
		{"consent db read refuses run insert", Write, Write,
			[]token.Detail{row("core", "read"), tables("core", tbl("items", "insert"))}, Access{}, "beyond read", None},
		{"consent star read refuses run insert", Write, Write,
			[]token.Detail{row("*", "read"), tables("core", tbl("items", "insert"))}, Access{}, "beyond read", None},
		{"consent star read keeps run select", Write, Write,
			[]token.Detail{row("*", "read"), tables("core", tbl("items", "insert", "select"))},
			Access{Level: Read, Tables: []TableGrant{tg("items", "select")}}, "", None},
		{"db consent beats star for run", Write, Write,
			[]token.Detail{row("*", "read"), row("core", "write"), tables("core", tbl("items", "delete"))},
			Access{Level: Write, Tables: []TableGrant{tg("items", "delete")}}, "", None},
		{"select only is read", Write, Write, []token.Detail{tables("core", tbl("items", "select"))},
			Access{Level: Read, Tables: []TableGrant{tg("items", "select")}}, "", None},
		{"verbs beyond bindings dropped", Read, Write, []token.Detail{tables("core", tbl("items", "update", "select"), tbl("big", "delete"))},
			Access{Level: Read, Tables: []TableGrant{tg("items", "select")}}, "", None},
		{"only verbs beyond scope", Write, Read, []token.Detail{tables("core", tbl("items", "delete"))}, Access{}, "beyond read", None},
		{"rows merged, duplicates once", Write, Write,
			[]token.Detail{tables("core", tbl("big", "update")), tables("core", tbl("big", "update"), tbl("items", "delete"))},
			Access{Level: Write, Tables: []TableGrant{tg("big", "update"), tg("items", "delete")}}, "", None},
		{"no scope", Write, None, []token.Detail{row("*", "write")}, Access{}, "", None},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Effective(tt.granted, tt.cap, tt.details, "core")
			if (tt.err == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("err = %v, want %q", err, tt.err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Effective = %+v, want %+v", got, tt.want)
			}
			if rc := RoleCap(tt.cap, tt.details); rc != tt.roleCap {
				t.Errorf("RoleCap = %s, want %s", rc, tt.roleCap)
			}
		})
	}
}

func TestCovers(t *testing.T) {
	grants := []RoleGrant{
		{Role: "w", Access: "SELECT", Database: "core"}, {Role: "w", Access: "INSERT", Database: "core"},
		{Role: "w", Access: "ALTER", Database: "core"},
		{Role: "s", Access: "SELECT", Database: "system", Table: "parts"},
		{Role: "s", Access: "SELECT", Database: "core", Table: "items", Column: true},
		{Role: "a", Access: "ALL"}, {Role: "a", Access: "INSERT", Database: "core", Table: "secret", PartialRevoke: true},
		{Role: "u", Access: "ALTER UPDATE", Database: "core", Table: "items"},
		{Role: "p", Access: "SELECT", Database: "rev"}, {Role: "p", Access: "INSERT", Database: "rev"},
		{Role: "p", Access: "SELECT", Database: "rev", Table: "sec", PartialRevoke: true},
	}
	tests := []struct {
		role, db, table, verb string
		want                  bool
	}{
		{"w", "core", "items", "select", true}, {"w", "core", "items", "insert", true},
		{"w", "core", "items", "update", true}, {"w", "core", "items", "delete", true},
		{"w", "otel", "spans", "select", false},
		{"s", "system", "parts", "select", true}, {"s", "system", "query_log", "select", false},
		{"s", "core", "items", "select", false}, // column-level only
		{"a", "otel", "spans", "delete", true}, {"a", "core", "secret", "insert", false}, {"a", "core", "secret", "select", true},
		{"u", "core", "items", "update", true}, {"u", "core", "items", "delete", false},
		{"a", "core", "other", "insert", false}, // a revoke anywhere in the database
		{"p", "rev", "secret", "select", false}, {"p", "rev", "open", "select", false}, {"p", "rev", "open", "insert", true},
		{"nobody", "core", "items", "select", false},
	}
	for _, tt := range tests {
		g := TableGrant{Database: tt.db, Table: tt.table, Verb: tt.verb}
		if got := Covers(grants, tt.role, g); got != tt.want {
			t.Errorf("Covers(%s, %+v) = %v, want %v", tt.role, g, got, tt.want)
		}
	}
}
