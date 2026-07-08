package profiles_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/3soos3/fit-issuer/internal/profiles"
)

func TestLoadMissingFile(t *testing.T) {
	r, err := profiles.Load("/nonexistent/profiles.yaml")
	if err != nil {
		t.Fatalf("Load missing file should not error: %v", err)
	}
	p := r.Public()
	if p == nil {
		t.Fatal("Public() should return default profile")
	}
	if p.Purpose == "" {
		t.Error("default public profile should have a purpose")
	}
}

func TestLoadFromFile(t *testing.T) {
	const yaml = `
profiles:
  public:
    authorized_tools:
      - get_technique
      - search_.*
    purpose: "public access"
    validity_days: 7
    invocation_types_permitted:
      - human_direct
  researcher:
    authorized_tools:
      - search_.*
    purpose: "research"
    validity_days: 14
`
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	r, err := profiles.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	pub := r.Public()
	if len(pub.AuthorizedTools) != 2 {
		t.Errorf("public tools: got %d, want 2", len(pub.AuthorizedTools))
	}
	if pub.ValidityDays != 7 {
		t.Errorf("public validity_days: got %d, want 7", pub.ValidityDays)
	}

	res, ok := r.Get("researcher")
	if !ok {
		t.Fatal("researcher profile not found")
	}
	if res.ValidityDays != 14 {
		t.Errorf("researcher validity_days: got %d, want 14", res.ValidityDays)
	}

	if _, ok := r.Get("unknown"); ok {
		t.Error("unknown profile should not exist")
	}
}

func TestLoadBadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte("{bad yaml: ["), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := profiles.Load(path); err == nil {
		t.Error("Load bad YAML should return error")
	}
}

func TestMerge(t *testing.T) {
	base := &profiles.Profile{
		AuthorizedTools: []string{"get_technique"},
		Purpose:         "default purpose",
		ValidityDays:    30,
	}
	req := &profiles.IssueRequest{
		InvestigationID:   "inv-1",
		AuthorizedAnalyst: "analyst@example.org",
		Purpose:           "override purpose",
	}
	out := profiles.Merge(base, req)
	if out.Purpose != "override purpose" {
		t.Errorf("Purpose should be overridden, got %q", out.Purpose)
	}
	if len(out.AuthorizedTools) != 1 || out.AuthorizedTools[0] != "get_technique" {
		t.Errorf("AuthorizedTools should come from base, got %v", out.AuthorizedTools)
	}
	if out.ValidDays != 30 {
		t.Errorf("ValidDays should come from base, got %d", out.ValidDays)
	}
}

func TestForResource(t *testing.T) {
	const yaml = `
profiles:
  public:
    authorized_tools: ["any_tool"]
    purpose: "public fallback"
  solveit:
    authorized_tools: ["search_technique"]
    audience: ["https://solve-it.example.org"]
    purpose: "solveit profile"
  hansken:
    authorized_tools: ["search_artifacts"]
    audience: ["https://hansken.example.org"]
    purpose: "hansken profile"
`
	dir := t.TempDir()
	path := dir + "/profiles.yaml"
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	r, err := profiles.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	t.Run("matches solveit audience", func(t *testing.T) {
		p := r.ForResource("https://solve-it.example.org")
		if p.Purpose != "solveit profile" {
			t.Errorf("got purpose %q, want solveit profile", p.Purpose)
		}
	})

	t.Run("matches hansken audience", func(t *testing.T) {
		p := r.ForResource("https://hansken.example.org")
		if p.Purpose != "hansken profile" {
			t.Errorf("got purpose %q, want hansken profile", p.Purpose)
		}
	})

	t.Run("no match falls back to public", func(t *testing.T) {
		p := r.ForResource("https://unknown.example.org")
		if p.Purpose != "public fallback" {
			t.Errorf("got purpose %q, want public fallback", p.Purpose)
		}
	})

	t.Run("empty resource falls back to public", func(t *testing.T) {
		p := r.ForResource("")
		if p.Purpose != "public fallback" {
			t.Errorf("got purpose %q, want public fallback", p.Purpose)
		}
	})
}

func TestMergeExplicitOverrides(t *testing.T) {
	base := &profiles.Profile{
		AuthorizedTools: []string{"get_technique"},
		ValidityDays:    30,
	}
	req := &profiles.IssueRequest{
		AuthorizedTools: []string{"search_.*"},
		ValidDays:       7,
	}
	out := profiles.Merge(base, req)
	if len(out.AuthorizedTools) != 1 || out.AuthorizedTools[0] != "search_.*" {
		t.Errorf("explicit AuthorizedTools should override base, got %v", out.AuthorizedTools)
	}
	if out.ValidDays != 7 {
		t.Errorf("explicit ValidDays should override base, got %d", out.ValidDays)
	}
}
