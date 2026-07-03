package profiles

import (
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// Profile holds the claim defaults for a named FIT profile.
type Profile struct {
	AuthorizedTools          []string `yaml:"authorized_tools"`
	Purpose                  string   `yaml:"purpose"`
	ValidityDays             int      `yaml:"validity_days"`
	InvocationTypesPermitted []string `yaml:"invocation_types_permitted"`
	LegalAuthority           string   `yaml:"legal_authority"`
	DataScope                string   `yaml:"data_scope"`
	Supervisor               string   `yaml:"supervisor"`
	Classification           string   `yaml:"classification"`
}

// Registry holds the loaded profile map.
type Registry struct {
	profiles map[string]*Profile
}

// Load reads profiles.yaml. If the file is absent, built-in defaults are used.
// Returns an error if the file exists but cannot be parsed.
func Load(path string) (*Registry, error) {
	r := &Registry{profiles: defaultProfiles()}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		slog.Info("profiles config not found, using defaults", "path", path)
		return r, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read profiles config: %w", err)
	}

	var raw struct {
		Profiles map[string]*Profile `yaml:"profiles"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse profiles config: %w", err)
	}
	for name, p := range raw.Profiles {
		r.profiles[name] = p
	}

	names := make([]string, 0, len(r.profiles))
	for n := range r.profiles {
		names = append(names, n)
	}
	slog.Info("profiles loaded", "profiles", names)
	return r, nil
}

// Get returns the named profile, or false if it does not exist.
func (r *Registry) Get(name string) (*Profile, bool) {
	p, ok := r.profiles[name]
	return p, ok
}

// Public returns the "public" profile (always present via defaults).
func (r *Registry) Public() *Profile {
	if p, ok := r.profiles["public"]; ok {
		return p
	}
	return defaultPublic()
}

// IssueRequest holds caller-supplied fields for POST /fit/issue.
type IssueRequest struct {
	Profile                  string   `json:"profile"`
	InvestigationID          string   `json:"investigation_id"`
	AuthorizedAnalyst        string   `json:"authorized_analyst"`
	AuthorizedTools          []string `json:"authorized_tools"`
	LegalAuthority           string   `json:"legal_authority"`
	Purpose                  string   `json:"purpose"`
	ValidDays                int      `json:"valid_days"`
	DataScope                string   `json:"data_scope"`
	InvocationTypesPermitted []string `json:"invocation_types_permitted"`
	Supervisor               string   `json:"supervisor"`
	Classification           string   `json:"classification"`
}

// Merge overlays explicit request fields on top of profile defaults.
// Non-zero values in req take priority; zero values fall back to base.
func Merge(base *Profile, req *IssueRequest) *IssueRequest {
	out := *req
	if len(out.AuthorizedTools) == 0         { out.AuthorizedTools = base.AuthorizedTools }
	if out.Purpose == ""                      { out.Purpose = base.Purpose }
	if out.ValidDays == 0                     { out.ValidDays = base.ValidityDays }
	if len(out.InvocationTypesPermitted) == 0 { out.InvocationTypesPermitted = base.InvocationTypesPermitted }
	if out.LegalAuthority == ""               { out.LegalAuthority = base.LegalAuthority }
	if out.DataScope == ""                    { out.DataScope = base.DataScope }
	if out.Supervisor == ""                   { out.Supervisor = base.Supervisor }
	if out.Classification == ""               { out.Classification = base.Classification }
	return &out
}

func defaultProfiles() map[string]*Profile {
	return map[string]*Profile{"public": defaultPublic()}
}

func defaultPublic() *Profile {
	return &Profile{
		Purpose:      "public access — non-evidentiary",
		ValidityDays: 30,
		InvocationTypesPermitted: []string{
			"human_direct", "agent_supervised", "agent_autonomous",
		},
	}
}
