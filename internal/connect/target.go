package connect

import (
	"fmt"
	"slices"
	"strings"
)

// SplitTarget splits a chauth address into its environment and the rest serve resolves. A known
// "<env>/" prefix always wins; otherwise the whole target, empty included, belongs to defaultEnv,
// and without one it is refused.
func SplitTarget(target, defaultEnv string, envs []string) (env, rest string, err error) {
	if head, tail, ok := strings.Cut(target, "/"); ok && slices.Contains(envs, head) {
		return head, tail, nil
	}
	if defaultEnv == "" {
		return "", "", fmt.Errorf("use <env>/<db>; environments: %s", strings.Join(envs, ", "))
	}
	return defaultEnv, target, nil
}
