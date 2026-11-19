package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// DetailsClaim holds RFC 9396 authorization details; DetailsType is the type chauth acts on.
const (
	DetailsClaim = "authorization_details"
	DetailsType  = "clickhouse"
)

// Detail is one authorization_details row: consent rows carry Actions, run-intent rows carry Tables.
type Detail struct {
	Type       string      `json:"type"`
	Locations  []string    `json:"locations"`
	Identifier string      `json:"identifier"`
	Actions    []string    `json:"actions,omitempty"`
	Tables     []TableRule `json:"tables,omitempty"`
}

// TableRule names one table of the row's database and the verbs a run may use on it.
type TableRule struct {
	Name  string   `json:"name"`
	Verbs []string `json:"verbs"`
}

var (
	actions = []string{"read", "write"}
	verbs   = []string{"select", "insert", "update", "delete"}
)

// ParseDetails reads the claim value raw: nil when the token has no claim, else the rows of type typ,
// possibly none. Rows of another type are skipped; anything unknown or malformed fails.
func ParseDetails(raw any, typ, audience string) ([]Detail, error) {
	if raw == nil {
		return nil, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var all []Detail
	if err := dec.Decode(&all); err != nil {
		return nil, fmt.Errorf("not an array of known rows: %v", err)
	}
	out := []Detail{}
	for i, d := range all {
		if d.Type != typ {
			continue
		}
		if err := checkDetail(d, audience); err != nil {
			return nil, fmt.Errorf("row %d: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func checkDetail(d Detail, audience string) error {
	switch {
	case len(d.Locations) != 1 || d.Locations[0] != audience:
		return fmt.Errorf("locations must be exactly [%q]", audience)
	case d.Identifier == "" || strings.Contains(d.Identifier, "/") || !printable(d.Identifier):
		return errors.New("identifier must be * or a database name")
	case len(d.Actions) > 0 && len(d.Tables) > 0:
		return errors.New("a row has actions or tables, not both")
	case len(d.Actions) == 0 && len(d.Tables) == 0:
		return errors.New("a row needs actions or tables")
	case len(d.Tables) > 0 && d.Identifier == "*":
		return errors.New("tables need a database identifier, not *")
	}
	for _, a := range d.Actions {
		if !slices.Contains(actions, a) {
			return fmt.Errorf("unknown action %q", a)
		}
	}
	for _, t := range d.Tables {
		if t.Name == "" || !printable(t.Name) {
			return errors.New("table name must be a non-empty table name")
		}
		if len(t.Verbs) == 0 {
			return fmt.Errorf("table %s has no verbs", t.Name)
		}
		for _, v := range t.Verbs {
			if !slices.Contains(verbs, v) {
				return fmt.Errorf("table %s: unknown verb %q", t.Name, v)
			}
		}
	}
	return nil
}

func printable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r == unicode.ReplacementChar || unicode.IsControl(r) })
}
