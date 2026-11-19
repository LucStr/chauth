package token

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseDetails(t *testing.T) {
	const aud = "https://clickhouse.example.com"
	tests := []struct {
		name, claim string // claim is JSON; "" means no claim
		want        []Detail
		err         string
	}{
		{"no claim", "", nil, ""},
		{"empty array denies all", `[]`, []Detail{}, ""},
		{"consent and run rows", `[
			{"type":"clickhouse","locations":["` + aud + `"],"identifier":"*","actions":["read"]},
			{"type":"clickhouse","locations":["` + aud + `"],"identifier":"core","tables":[{"name":"items","verbs":["insert","select"]}]}]`,
			[]Detail{
				{Type: "clickhouse", Locations: []string{aud}, Identifier: "*", Actions: []string{"read"}},
				{Type: "clickhouse", Locations: []string{aud}, Identifier: "core", Tables: []TableRule{{Name: "items", Verbs: []string{"insert", "select"}}}},
			}, ""},
		{"other type skipped", `[{"type":"postgres","locations":["https://pg"],"identifier":"a/b","actions":["write"]}]`, []Detail{}, ""},
		{"unknown row field", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"*","actions":["read"],"rows":1}]`, nil, "unknown field"},
		{"unknown table field", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"core","tables":[{"name":"items","verbs":["select"],"where":"x"}]}]`, nil, "unknown field"},
		{"wrong audience", `[{"type":"clickhouse","locations":["https://other"],"identifier":"*","actions":["read"]}]`, nil, "locations"},
		{"two locations", `[{"type":"clickhouse","locations":["` + aud + `","` + aud + `"],"identifier":"*","actions":["read"]}]`, nil, "locations"},
		{"instance-qualified identifier", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"main/core","actions":["read"]}]`, nil, "identifier"},
		{"empty identifier", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"","actions":["read"]}]`, nil, "identifier"},
		{"unknown action", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"*","actions":["admin"]}]`, nil, "unknown action"},
		{"actions and tables", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"core","actions":["read"],"tables":[{"name":"items","verbs":["select"]}]}]`, nil, "not both"},
		{"neither", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"core"}]`, nil, "needs actions"},
		{"tables on *", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"*","tables":[{"name":"items","verbs":["select"]}]}]`, nil, "not *"},
		{"unknown verb", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"core","tables":[{"name":"items","verbs":["drop"]}]}]`, nil, "unknown verb"},
		{"no verbs", `[{"type":"clickhouse","locations":["` + aud + `"],"identifier":"core","tables":[{"name":"items","verbs":[]}]}]`, nil, "no verbs"},
		{"not an array", `{"type":"clickhouse"}`, nil, "not an array"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw any
			if tt.claim != "" {
				if err := json.Unmarshal([]byte(tt.claim), &raw); err != nil {
					t.Fatal(err)
				}
			}
			got, err := ParseDetails(raw, DetailsType, aud)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, tt.want)
			}
		})
	}
}
