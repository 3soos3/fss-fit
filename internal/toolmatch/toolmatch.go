package toolmatch

import (
	"fmt"
	"regexp"
)

// IsCatchAll returns true if the anchored pattern would match every possible
// tool name. It checks a diverse sample of strings; if all match, the pattern
// is a catch-all. This handles both ".*" (matches empty) and ".+" (matches any
// non-empty string — sufficient to authorize every tool call in practice).
func IsCatchAll(pattern string) bool {
	if _, err := regexp.Compile(pattern); err != nil {
		return false
	}
	anchored := "^(?:" + pattern + ")$"
	samples := []string{"a", "get_technique", "search_hash", "delete_files", "1", "_x_"}
	for _, s := range samples {
		if matched, _ := regexp.MatchString(anchored, s); !matched {
			return false
		}
	}
	return true
}

// Validate compiles each pattern and rejects invalid regexps and catch-all patterns.
func Validate(patterns []string) error {
	for _, p := range patterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("invalid regexp %q: %w", p, err)
		}
		if IsCatchAll(p) {
			return fmt.Errorf("catch-all pattern %q is not permitted", p)
		}
	}
	return nil
}

// Match returns true if toolName is matched by at least one anchored pattern.
func Match(patterns []string, toolName string) bool {
	for _, p := range patterns {
		if matched, _ := regexp.MatchString("^(?:"+p+")$", toolName); matched {
			return true
		}
	}
	return false
}
