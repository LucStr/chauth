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

// TestNames: no subject gives a person's temp user the self-test user's shape, and both keep the
// prefix the admin's CREATE USER grant and the sweep match.
func TestNames(t *testing.T) {
	m := &Manager{prefix: "chauth_tmp_", nonce: "abcdef"}
	for _, sub := range []string{"selftest", "selftest_x", "_selftest", "__", "Self_Test-1", "", "üñî"} {
		user, self := m.userName(sub), m.selfTestName()
		if !strings.HasPrefix(user, m.prefix) || strings.HasPrefix(user, m.prefix+"_") || !validName(user) {
			t.Errorf("subject %q: user %q", sub, user)
		}
		if !strings.HasPrefix(self, m.prefix+"_selftest_"+m.nonce) || !validName(self) {
			t.Errorf("self-test user %q", self)
		}
	}
}
