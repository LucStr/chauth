package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// ParseDetails reads the JSON value of a present claim: the rows of type typ, possibly none. Rows of
// another type are skipped; null, a non-array, or anything unknown or malformed fails.
func ParseDetails(raw json.RawMessage, typ, audience string) ([]Detail, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil || items == nil {
		return nil, errors.New("must be an array")
	}
	for i, item := range items {
		row, err := exactFields(item, "type", "locations", "identifier", "actions", "tables")
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i, err)
		}
		if t, ok := row["tables"]; ok {
			var rules []json.RawMessage
			if err := json.Unmarshal(t, &rules); err != nil {
				return nil, fmt.Errorf("row %d: tables must be an array", i)
			}
			for _, r := range rules {
				if _, err := exactFields(r, "name", "verbs"); err != nil {
					return nil, fmt.Errorf("row %d: table: %w", i, err)
				}
			}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
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

// exactFields reads one JSON object whose keys must each be one of allowed, spelled exactly, and
// appear once: encoding/json matches keys ignoring case (Unicode folding) and lets the last duplicate win.
func exactFields(b []byte, allowed ...string) (map[string]json.RawMessage, error) {
	fields, err := ObjectFields(b)
	if err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	for _, f := range fields {
		if !slices.Contains(allowed, f.Key) {
			return nil, fmt.Errorf("unknown field %q", f.Key)
		}
		if _, dup := out[f.Key]; dup {
			return nil, fmt.Errorf("duplicate field %q", f.Key)
		}
		out[f.Key] = f.Value
	}
	return out, nil
}

// Field is one member of a JSON object, in the order written.
type Field struct {
	Key   string
	Value json.RawMessage
}

// ObjectFields lists the members of the JSON object b, duplicates included.
func ObjectFields(b []byte) ([]Field, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("must be an object")
	}
	var out []Field
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		f := Field{Key: t.(string)}
		if err := dec.Decode(&f.Value); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the object")
	}
	return out, nil
}
