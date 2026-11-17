package chusers

import (
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	allowed := strings.Join(passwordClasses, "")
	seen := map[string]bool{}
	for range 10000 {
		p := password()
		if len(p) != 32 || strings.Trim(p, allowed) != "" || seen[p] {
			t.Fatalf("password %q: length %d, outside the allowed set or repeated", p, len(p))
		}
		seen[p] = true
		for _, class := range passwordClasses {
			n := 0
			for _, r := range p {
				if strings.ContainsRune(class, r) {
					n++
				}
			}
			if n < 2 {
				t.Fatalf("password %q has %d of %q, want at least 2", p, n, class)
			}
		}
	}
}
