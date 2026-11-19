package chproxy

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/LucStr/chauth/internal/chapi"
	"github.com/LucStr/chauth/internal/chtest"
	"github.com/LucStr/chauth/internal/chwire"
)

// TestAuthorizationDetails: consent rows narrow whole databases, run rows narrow to declared tables
// and verbs, and ClickHouse itself refuses everything else with ACCESS_DENIED.
func TestAuthorizationDetails(t *testing.T) {
	h := start(t, chRole("everything", `{instance: main, database: "*", level: write}`)+binding("everything", "everything", user(chtest.User))+queryLog, nil)
	row := func(id string, kv ...any) map[string]any {
		m := map[string]any{"type": "clickhouse", "locations": []string{chtest.Audience}, "identifier": id}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	tok := func(details ...map[string]any) string {
		c := chtest.Claims{Scope: "clickhouse:write"}
		if details != nil {
			c.Details = details
		}
		return shared.Issuer.Token(c)
	}
	run := tok(row("core", "tables", []any{
		map[string]any{"name": "items", "verbs": []string{"insert", "select", "delete"}},
	}))
	consent := tok(row("*", "actions", []string{"read"}), row("core", "actions", []string{"write"}))
	none := tok()
	null := shared.Issuer.Token(chtest.Claims{Scope: "clickhouse:write", Details: json.RawMessage("null")})
	denied := int32(chwire.CodeAccessDenied)
	tests := []struct {
		name, tok, db, stmt string
		code                int32 // 0 ok, else the ClickHouse error code
	}{
		{"run: insert declared table", run, "core", "INSERT INTO core.items VALUES (42)", 0},
		{"run: select declared table", run, "core", "SELECT count() FROM core.items", 0},
		{"run: delete declared table", run, "core", "ALTER TABLE core.items DELETE WHERE id = 4242", 0},
		{"run: insert undeclared table", run, "core", "INSERT INTO core.big VALUES (42)", denied},
		{"run: select undeclared table", run, "core", "SELECT count() FROM core.big", denied},
		{"run: no DDL on declared table", run, "core", "ALTER TABLE core.items ADD COLUMN x UInt8", denied},
		{"run: no DDL in the database", run, "core", "CREATE TABLE core.probe (a UInt8) ENGINE = Memory", denied},
		{"run: other database", run, "core", "SELECT count() FROM otel.spans", denied},
		{"run: named role dropped", run, "core", "SELECT count() FROM system.query_log", denied},
		{"run: undeclared database refused", run, "otel", "SELECT 1", denied},
		{"consent: write override", consent, "core", "INSERT INTO core.big VALUES (42)", 0},
		{"consent: star is read", consent, "otel", "SELECT count() FROM otel.spans", 0},
		{"consent: star refuses insert", consent, "otel", "INSERT INTO otel.spans VALUES (42)", denied},
		{"consent: named role follows star", consent, "core", "SELECT count() FROM system.query_log", 0},
		{"no claim: today's access", none, "otel", "INSERT INTO otel.spans VALUES (42)", 0},
		{"null claim refused", null, "otel", "SELECT 1", denied},
	}
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("native", func(t *testing.T) {
				c, err := h.nativeOpen(ctx, tt.db, tt.tok, nil)
				if err == nil {
					defer c.Close()
					err = c.Exec(ctx, tt.stmt)
				}
				if code := nativeCode(err); err != nil && code != tt.code || err == nil && tt.code != 0 {
					t.Errorf("%v (code %d), want code %d", err, code, tt.code)
				}
			})
			t.Run("http", func(t *testing.T) {
				status, body, hdr := h.do(t, "database="+tt.db, nil, tt.tok, tt.stmt)
				code, _ := strconv.Atoi(hdr.Get("X-ClickHouse-Exception-Code"))
				if status == 200 != (tt.code == 0) || tt.code != 0 && int32(code) != tt.code {
					t.Errorf("%d %s, want code %d", status, body, tt.code)
				}
			})
		})
	}

	for _, tt := range []struct {
		tok, db string
		status  int
		tables  []string // nil: skip the check
	}{
		{consent, "core", 200, []string{"big", "items"}}, {consent, "otel", 200, []string{"spans"}}, {none, "main/core", 200, []string{"big", "items"}},
		{run, "core", 200, []string{"items"}}, {run, "otel", 403, nil},
		{consent, "nope", 404, nil}, {consent, "", 404, nil}, {consent, "main/nope", 404, nil}, {"", "core", 401, nil},
	} {
		var rows []chapi.Table
		status := getJSON(t, h.url+chapi.TablesPath+"?db="+tt.db, tt.tok, &rows)
		var names []string
		for _, r := range rows {
			names = append(names, r.Table)
			if r.Table == "big" && r.EstimatedRows < 4000000 {
				t.Errorf("tables %s: %+v", tt.db, r)
			}
		}
		if status != tt.status || tt.tables != nil && strings.Join(names, ",") != strings.Join(tt.tables, ",") {
			t.Errorf("tables %q: %d %v, want %d %v", tt.db, status, names, tt.status, tt.tables)
		}
	}
}
