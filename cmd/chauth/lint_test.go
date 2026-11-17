package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLint(t *testing.T) {
	writeDir := func(content string) string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "roles.yaml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	role := func(grant string) string {
		return writeDir("apiVersion: chauth.dev/v1alpha1\nkind: ChRole\nmetadata: {name: x}\nspec: {grants: [" + grant + "]}\n")
	}
	const cfg = "../../examples/config.yaml"
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"examples without config", []string{"../../examples/rbac"}, 0},
		{"examples with config", []string{"--config", cfg, "../../examples/rbac"}, 0},
		{"write on every database, system read-only", []string{"--config", cfg, role(`{instance: main, database: "*", level: write}`)}, 0},
		{"explicit write on a read-only database", []string{"--config", cfg, role("{instance: main, database: system, level: write}")}, 1},
		{"read-only database is not checked without config", []string{role("{instance: main, database: system, level: write}")}, 0},
		{"a foreign kind", []string{writeDir("apiVersion: chauth.dev/v1alpha1\nkind: ClusterRole\nmetadata: {name: x}\nspec: {}\n")}, 1},
		{"missing directory", []string{"../../examples/missing"}, 1},
		{"directory without rule files", []string{t.TempDir()}, 1},
	}
	for _, tt := range tests {
		if got := lint(tt.args); got != tt.want {
			t.Errorf("%s: lint %v = %d, want %d", tt.name, tt.args, got, tt.want)
		}
	}
}
