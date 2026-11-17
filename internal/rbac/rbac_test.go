package rbac

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	instances = Instances{"main": {"core", "otel", "system"}}
	roles     = Instances{"main": {"chauth_querylog_read"}}
)

const header = "apiVersion: chauth.dev/v1alpha1\n"

func TestLint(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		instances Instances
		want      []string // each a substring of one error, in order; empty = valid
		warn      []string
	}{
		{"database, wildcard and named-role grants, bindings to own and generated roles", header + `kind: ChRole
metadata: {name: analytics}
spec:
  grants:
    - {instance: main, database: core, level: write}
    - {instance: main, database: "*", level: read}
    - {instance: main, role: chauth_querylog_read, level: read}
---
` + header + `kind: ChRoleBinding
metadata: {name: analysts}
spec:
  roleRef: {kind: ChRole, name: analytics}
  subjects: [{kind: Group, name: analysts}]
---
` + header + `kind: ChRoleBinding
metadata: {name: alice-otel}
spec:
  roleRef: {kind: ChRole, name: main.otel.read}
  subjects: [{kind: User, name: alice@example.com}]
`, instances, nil, nil},
		{"unknown field", header + `kind: ChRoleBinding
metadata: {name: x}
spec:
  roleRef: {kind: ChRole, name: main.core.read}
  subject: [{kind: User, name: a}]
`, instances, []string{"a.yaml:6: unknown field spec.subject", "a.yaml:5: spec.subjects is required"}, nil},
		{"wrong apiVersion and kind", `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: x}
spec: {}
`, instances, []string{"a.yaml:1: apiVersion must be chauth.dev/v1alpha1", "a.yaml:2: kind must be ChRole or ChRoleBinding"}, nil},
		{"duplicate binding", header + `kind: ChRoleBinding
metadata: {name: x}
spec: {roleRef: {kind: ChRole, name: main.core.read}, subjects: [{kind: User, name: a}]}
---
` + header + `kind: ChRoleBinding
metadata: {name: x}
spec: {roleRef: {kind: ChRole, name: main.otel.read}, subjects: [{kind: User, name: b}]}
`, instances, []string{"a.yaml:6: duplicate ChRoleBinding x, first defined at a.yaml:1"}, nil},
		{"role with a built-in name", header + `kind: ChRole
metadata: {name: main.core.read}
spec: {grants: [{instance: main, database: core, level: write}]}
`, instances, []string{"a.yaml:1: ChRole main.core.read has the name of a built-in role"}, nil},
		{"roleRef to a missing role", header + `kind: ChRoleBinding
metadata: {name: x}
spec:
  roleRef: {kind: ChRole, name: main.billing.read}
  subjects: [{kind: User, name: a}]
`, instances, []string{"a.yaml:5: roleRef main.billing.read names no ChRole"}, nil},
		{"no broad built-ins", header + `kind: ChRoleBinding
metadata: {name: x}
spec: {roleRef: {kind: ChRole, name: admin}, subjects: [{kind: User, name: a}]}
`, instances, []string{"a.yaml:4: roleRef admin names no ChRole"}, nil},
		{"grants outside the config", header + `kind: ChRole
metadata: {name: x}
spec:
  grants:
    - {instance: logs, database: otel, level: read}
    - {instance: main, database: billing, level: read}
`, instances, []string{"a.yaml:6: instance logs is not configured", "a.yaml:7: database main/billing is not configured"}, nil},
		{"database and role together, bad role name", header + `kind: ChRole
metadata: {name: x}
spec:
  grants:
    - {instance: main, database: core, role: chauth_querylog_read, level: read}
    - {instance: main, role: "Bad Role", level: read}
`, instances, []string{"a.yaml:6: spec.grants[] names both database and role", `a.yaml:7: spec.grants[].role "Bad Role" must be`}, nil},
		{"role outside the allowlist", header + `kind: ChRole
metadata: {name: x}
spec: {grants: [{instance: main, role: chauth_secrets, level: read}]}
`, instances, []string{"a.yaml:4: role chauth_secrets is not in instance main's roles allowlist"}, nil},
		{"bad subject kind and level", header + `kind: ChRole
metadata: {name: x}
spec: {grants: [{instance: main, database: core, level: admin}]}
---
` + header + `kind: ChRoleBinding
metadata: {name: y}
spec:
  roleRef: {kind: ChRole, name: x}
  subjects:
    - {kind: ServiceAccount, name: a}
`, instances, []string{"a.yaml:4: spec.grants[].level must be read or write", "a.yaml:12: spec.subjects[].kind must be User or Group"}, nil},
		{"empty file", "", instances, []string{"a.yaml:1: file has no ChRole or ChRoleBinding"}, nil},
		{"file with only comments", "# bindings go here\n---\n", instances, []string{"a.yaml:1: file has no ChRole or ChRoleBinding"}, nil},
		{"broken YAML", header + "kind: ChRole\nmetadata: {name: x\n", instances, []string{"a.yaml:2: yaml: line 2:"}, nil},
		{"without a config, instances and generated roles are not checked", header + `kind: ChRole
metadata: {name: x}
spec: {grants: [{instance: logs, database: otel, level: read}]}
---
` + header + `kind: ChRoleBinding
metadata: {name: y}
spec: {roleRef: {kind: ChRole, name: logs.otel.write}, subjects: [{kind: User, name: a}]}
`, nil, nil, nil},
		{"uppercase user is valid, warned only under exact matching", header + `kind: ChRoleBinding
metadata: {name: x}
spec:
  roleRef: {kind: ChRole, name: main.core.read}
  subjects: [{kind: User, name: Alice@example.com}, {kind: Group, name: Admins}]
`, instances, nil, []string{"a.yaml:6: warning: User Alice@example.com has uppercase letters"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []File{{Name: "a.yaml", Data: []byte(tt.yaml)}}
			_, err := Load(files, tt.instances, roles)
			res, _ := Parse(files)
			if w := res.Warnings(false); len(w) != len(tt.warn) || len(w) > 0 && !strings.Contains(w.Error(), tt.warn[0]) {
				t.Errorf("exact matching: warnings = %v, want %q", w, tt.warn)
			}
			if w := res.Warnings(true); len(w) > 0 {
				t.Errorf("case-insensitive matching: warnings = %v, want none", w)
			}
			var got []string
			if err != nil {
				got = strings.Split(err.Error(), "\n")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("errors:\n%s\nwant %d matching %q", strings.Join(got, "\n"), len(tt.want), tt.want)
			}
			for i := range got {
				if !strings.Contains(got[i], tt.want[i]) {
					t.Errorf("error %d = %q, want it to contain %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestUserMatching(t *testing.T) {
	b := &Binding{Subjects: []Subject{{Kind: "User", Name: "Tom_Mitchell@example.com"}}}
	tests := []struct {
		user string
		fold bool
		want bool
	}{
		{"Tom_Mitchell@example.com", false, true},
		{"tom_mitchell@example.com", false, false},
		{"tom_mitchell@example.com", true, true},
		{"TOM_MITCHELL@EXAMPLE.COM", true, true},
		{"tom.mitchell@example.com", true, false},
	}
	for _, tt := range tests {
		if got := b.matches(Who{User: tt.user, FoldUser: tt.fold}); got != tt.want {
			t.Errorf("user %q fold %v: match = %v, want %v", tt.user, tt.fold, got, tt.want)
		}
	}
}

func TestReloadWaitsForFilesToSettle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bindings.yaml")
	write := func(user string) {
		b := header + "kind: ChRoleBinding\nmetadata: {name: alice}\nspec:\n  roleRef: {kind: ChRole, name: main.core.read}\n" +
			"  subjects: [{kind: User, name: " + user + "}]\n"
		if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store := NewStore(instances, roles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	write("first@example.com")

	// The file changes between the two reads: not settled, nothing to load yet.
	store.sleep = func(time.Duration) { write("second@example.com") }
	if _, settled, err := store.readSettled(dir); err != nil || settled {
		t.Fatalf("settled = %v, err %v; want a changing file left for the next tick", settled, err)
	}

	store.sleep = func(time.Duration) {}
	files, settled, err := store.readSettled(dir)
	if err != nil || !settled {
		t.Fatalf("settled = %v, err %v; want two identical reads to settle", settled, err)
	}
	if err := store.Update(files); err != nil {
		t.Fatal(err)
	}
	if l := store.Policy().Grants(Who{User: "second@example.com"}, "main", Write).Databases["core"]; l != Read {
		t.Fatalf("level = %v, want read from the settled file", l)
	}
}

func TestLastValidWins(t *testing.T) {
	dir := t.TempDir()
	// Replace the file atomically, as a ConfigMap update does: an in-place write can be read while
	// empty, and an empty set is valid, so the watcher would load "no bindings" in between.
	write := func(content string) {
		tmp := filepath.Join(dir, ".bindings.tmp")
		if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "bindings.yaml")); err != nil {
			t.Fatal(err)
		}
	}
	bindTo := func(role string) string {
		return header + "kind: ChRoleBinding\nmetadata: {name: alice}\nspec:\n  roleRef: {kind: ChRole, name: " + role +
			"}\n  subjects: [{kind: User, name: alice@example.com}]\n"
	}
	level := func(s *Store) Level {
		if s.Policy() == nil {
			return None
		}
		return s.Policy().Grants(Who{User: "alice@example.com"}, "main", Write).Databases["core"]
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	store := NewStore(instances, roles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	write(bindTo("main.core.missing"))
	go store.WatchDir(ctx, dir, 20*time.Millisecond)
	waitFor("the first invalid set to be rejected", func() bool { return store.Status().Rejected != nil })
	if store.Status().Loaded || store.Policy() != nil {
		t.Fatal("an invalid first set must leave serve without rules")
	}

	write(bindTo("main.core.read"))
	waitFor("the valid set to load", func() bool { return store.Status().Loaded && store.Status().Rejected == nil })
	if level(store) != Read {
		t.Fatalf("level = %v, want read", level(store))
	}

	write("")
	waitFor("the emptied file to be rejected", func() bool { return store.Status().Rejected != nil })
	if level(store) != Read {
		t.Fatalf("after emptying the file: level %v, want the previous set (read) still live", level(store))
	}
	write(bindTo("main.core.read"))
	waitFor("the restored set to clear the rejection", func() bool { return store.Status().Rejected == nil })

	write(bindTo("main.core.write") + "  extra: field\n")
	waitFor("the bad change to be rejected", func() bool { return store.Status().Rejected != nil })
	if !store.Status().Loaded || level(store) != Read {
		t.Fatalf("after a rejected change: loaded %v, level %v; want the previous set (read) still live", store.Status().Loaded, level(store))
	}

	write(bindTo("main.core.write"))
	waitFor("the fixed set to load", func() bool { return store.Status().Rejected == nil })
	if level(store) != Write {
		t.Fatalf("level = %v, want write", level(store))
	}
}

func TestGrants(t *testing.T) {
	chInstances := Instances{"main": {"core", "otel"}, "other": {"core"}}
	policy, err := Load([]File{{Name: "a.yaml", Data: []byte(header + `kind: ChRole
metadata: {name: analytics}
spec:
  grants:
    - {instance: main, database: "*", level: read}
    - {instance: main, database: core, level: write}
    - {instance: main, role: querylog, level: read}
    - {instance: main, role: ddl_audit, level: write}
---
` + header + `kind: ChRoleBinding
metadata: {name: analysts}
spec: {roleRef: {kind: ChRole, name: analytics}, subjects: [{kind: Group, name: analysts}]}
---
` + header + `kind: ChRoleBinding
metadata: {name: alice}
spec: {roleRef: {kind: ChRole, name: other.core.write}, subjects: [{kind: User, name: alice@example.com}]}
`)}}, chInstances, Instances{"main": {"querylog", "ddl_audit"}})
	if err != nil {
		t.Fatal(err)
	}
	analyst := Who{User: "alice@example.com", Groups: []string{"analysts"}}
	tests := []struct {
		who      Who
		instance string
		cap      Level
		dbs      map[string]Level
		roles    []string
		bindings []string
	}{
		{analyst, "main", Write, map[string]Level{"core": Write, "otel": Read}, []string{"ddl_audit", "querylog"}, []string{"analysts"}},
		{analyst, "main", Read, map[string]Level{"core": Read, "otel": Read}, []string{"querylog"}, []string{"analysts"}},
		{analyst, "main", None, map[string]Level{}, nil, nil},
		{analyst, "other", Read, map[string]Level{"core": Read}, nil, []string{"alice"}},
		{Who{User: "someone@example.com"}, "main", Write, map[string]Level{}, nil, nil},
	}
	for i, tt := range tests {
		g := policy.Grants(tt.who, tt.instance, tt.cap)
		if !reflect.DeepEqual(g.Databases, tt.dbs) || !slices.Equal(g.Roles, tt.roles) || !slices.Equal(g.Bindings, tt.bindings) {
			t.Errorf("row %d: got %+v, want %v %v %v", i, g, tt.dbs, tt.roles, tt.bindings)
		}
	}
}

// TestRulesDirGone: a missing, unreadable or emptied directory is a rejected load, at startup and
// at reload; the last valid set stays live.
func TestRulesDirGone(t *testing.T) {
	valid := header + "kind: ChRoleBinding\nmetadata: {name: alice}\nspec:\n  roleRef: {kind: ChRole, name: main.core.read}\n" +
		"  subjects: [{kind: User, name: alice@example.com}]\n"
	tests := []struct {
		name     string
		breakDir func(dir string) error
	}{
		{"missing", os.RemoveAll},
		{"unreadable", func(dir string) error { return os.Chmod(dir, 0) }},
		{"no rule files", func(dir string) error {
			if err := os.Remove(filepath.Join(dir, "rules.yaml")); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte("resources: []\n"), 0o600)
		}},
	}
	for _, tt := range tests {
		for _, phase := range []string{"startup", "reload"} {
			t.Run(tt.name+" at "+phase, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "rbac")
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
				if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(valid), 0o600); err != nil {
					t.Fatal(err)
				}
				store := NewStore(instances, roles, slog.New(slog.NewTextHandler(io.Discard, nil)))
				store.Settle = 0
				var rejected atomic.Int32
				store.OnLoad = func(err error) {
					if err != nil {
						rejected.Add(1)
					}
				}
				if phase == "startup" {
					if err := tt.breakDir(dir); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go store.WatchDir(ctx, dir, 10*time.Millisecond)
				if phase == "reload" {
					waitUntil(t, func() bool { return store.Status().Loaded })
					if err := tt.breakDir(dir); err != nil {
						t.Fatal(err)
					}
				}
				waitUntil(t, func() bool { return rejected.Load() > 0 && store.Status().Rejected != nil })
				st := store.Status()
				if phase == "startup" && (st.Loaded || store.Policy() != nil) {
					t.Fatal("serve has rules from a directory that holds none")
				}
				if phase == "reload" && (!st.Loaded || store.Policy().Grants(Who{User: "alice@example.com"}, "main", Write).Databases["core"] != Read) {
					t.Fatal("the last valid set was replaced")
				}
			})
		}
	}
	if _, err := ReadDir(t.TempDir()); err == nil || !strings.Contains(err.Error(), "holds no *.yaml rule file") {
		t.Errorf("ReadDir of an empty directory: %v", err)
	}
}

func waitUntil(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
	}
}
