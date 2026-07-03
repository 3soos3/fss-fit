package toolmatch_test

import (
	"testing"

	"github.com/3soos3/fit-issuer/internal/toolmatch"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		patterns []string
		tool     string
		want     bool
	}{
		{[]string{"get_technique"}, "get_technique", true},
		{[]string{"get_technique"}, "get_technique_v2", false},
		{[]string{"get_technique"}, "other", false},
		{[]string{"search_.*"}, "search_technique", true},
		{[]string{"search_.*"}, "search_hash", true},
		{[]string{"search_.*"}, "get_technique", false},
		// anchoring: "search_" must not match "search_technique"
		{[]string{"search_"}, "search_technique", false},
		{[]string{"search_"}, "search_", true},
		{[]string{}, "anything", false},
		{[]string{"get_technique", "search_.*"}, "search_hash", true},
		{[]string{"get_technique", "search_.*"}, "delete_all", false},
	}
	for _, tt := range tests {
		got := toolmatch.Match(tt.patterns, tt.tool)
		if got != tt.want {
			t.Errorf("Match(%v, %q) = %v, want %v", tt.patterns, tt.tool, got, tt.want)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := toolmatch.Validate([]string{"get_technique", "search_.*"}); err != nil {
		t.Errorf("unexpected error for valid patterns: %v", err)
	}
	for _, p := range []string{".*", ".+", "^.*$", "^.+$"} {
		if err := toolmatch.Validate([]string{p}); err == nil {
			t.Errorf("Validate(%q) should have returned error", p)
		}
	}
	if err := toolmatch.Validate([]string{"[unclosed"}); err == nil {
		t.Error("Validate([unclosed) should have returned error")
	}
}

func TestIsCatchAll(t *testing.T) {
	if !toolmatch.IsCatchAll(".*") {
		t.Error(".* should be catch-all")
	}
	if !toolmatch.IsCatchAll(".+") {
		t.Error(".+ should be catch-all")
	}
	if toolmatch.IsCatchAll("get_technique") {
		t.Error("get_technique should not be catch-all")
	}
	if toolmatch.IsCatchAll("search_.*") {
		t.Error("search_.* should not be catch-all")
	}
}
