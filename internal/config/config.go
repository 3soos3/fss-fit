package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	IssuerURL           string
	JWKSURL             string
	OAuthJWKSURL        string
	OAuthIssuerURL      string
	Audience            []string
	DefaultValidityDays int
	AuthorityToken      string
	DataDir             string
	ProfilesConfig      string
}

func Load() (*Config, error) {
	c := &Config{
		IssuerURL:           getenv("FIT_ISSUER_URL", ""),
		JWKSURL:             getenv("FIT_JWKS_URL", ""),
		OAuthJWKSURL:        getenv("OAUTH_JWKS_URL", ""),
		OAuthIssuerURL:      getenv("OAUTH_ISSUER_URL", ""),
		DefaultValidityDays: 30,
		AuthorityToken:      getenv("FIT_AUTHORITY_TOKEN", ""),
		DataDir:             getenv("FIT_DATA_DIR", "/data"),
	}
	c.ProfilesConfig = getenv("FIT_PROFILES_CONFIG", c.DataDir+"/profiles.yaml")

	if raw := getenv("FIT_AUDIENCE", ""); raw != "" {
		for _, a := range strings.Split(raw, ",") {
			if a = strings.TrimSpace(a); a != "" {
				c.Audience = append(c.Audience, a)
			}
		}
	}

	if raw := getenv("FIT_DEFAULT_VALIDITY_DAYS", ""); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("FIT_DEFAULT_VALIDITY_DAYS must be a positive integer")
		}
		c.DefaultValidityDays = n
	}

	if c.OAuthIssuerURL == "" && c.OAuthJWKSURL != "" {
		u := strings.TrimSuffix(c.OAuthJWKSURL, "/keys")
		u = strings.TrimSuffix(u, "/jwks")
		c.OAuthIssuerURL = u
	}

	var missing []string
	if c.IssuerURL == ""      { missing = append(missing, "FIT_ISSUER_URL") }
	if c.JWKSURL == ""        { missing = append(missing, "FIT_JWKS_URL") }
	if c.OAuthJWKSURL == ""   { missing = append(missing, "OAUTH_JWKS_URL") }
	if c.AuthorityToken == "" { missing = append(missing, "FIT_AUTHORITY_TOKEN") }
	if len(c.Audience) == 0   { missing = append(missing, "FIT_AUDIENCE") }
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
