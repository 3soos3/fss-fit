package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/oauthproxy"
	"github.com/3soos3/fit-issuer/internal/profiles"
	"github.com/3soos3/fit-issuer/internal/tokens"
)

// Login handles POST /fit/login: validates an OIDC Bearer JWT and issues a public FIT.
// oauthJWKS is fetched and verified at startup (passed from main); it is re-fetched
// once on signature failure to handle key rotation without a server restart.
func Login(cfg *config.Config, ks *keys.KeyStore, reg *profiles.Registry, oauthJWKS jwk.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerToken(r)
		if bearer == "" {
			errJSON(w, http.StatusUnauthorized, "missing Bearer token")
			return
		}

		sub, err := validateOIDCToken(bearer, cfg.OAuthIssuerURL, cfg.OAuthJWKSURL, oauthJWKS)
		if err != nil {
			errJSON(w, http.StatusUnauthorized, "invalid OIDC token")
			return
		}

		resource := r.URL.Query().Get("resource")
		compact, err := buildPublicFIT(cfg, ks, reg, sub, resource)
		if err != nil {
			slog.Error("build FIT", "err", err)
			errJSON(w, http.StatusInternalServerError, "failed to issue FIT")
			return
		}

		slog.Info("FIT_ISSUED",
			"event", "FIT_ISSUED",
			"issued_by", "public-login",
			"investigation_id", tokens.PublicInvestigationID(sub),
			"authorized_analyst", sub,
			"resource", resource,
		)
		writeJSON(w, http.StatusOK, map[string]string{"fit": compact})
	}
}

// MakeLoginFunc returns an oauthproxy.LoginFunc that validates an OIDC token and
// issues a FIT scoped to the profile matching the resource URL.
func MakeLoginFunc(cfg *config.Config, ks *keys.KeyStore, reg *profiles.Registry, oauthJWKS jwk.Set) oauthproxy.LoginFunc {
	return func(dexIDToken, resource string) (string, error) {
		sub, err := validateOIDCToken(dexIDToken, cfg.OAuthIssuerURL, cfg.OAuthJWKSURL, oauthJWKS)
		if err != nil {
			return "", fmt.Errorf("invalid OIDC token: %w", err)
		}
		return buildPublicFIT(cfg, ks, reg, sub, resource)
	}
}

// validateOIDCToken parses and validates an OIDC JWT, returning the subject.
// On signature failure it re-fetches the JWKS once to handle key rotation.
func validateOIDCToken(token, issuerURL, jwksURL string, oauthJWKS jwk.Set) (string, error) {
	tok, err := jwt.Parse([]byte(token),
		jwt.WithKeySet(oauthJWKS),
		jwt.WithIssuer(issuerURL),
		jwt.WithValidate(true),
	)
	if err != nil {
		fresh, ferr := jwk.Fetch(context.Background(), jwksURL)
		if ferr == nil {
			tok, err = jwt.Parse([]byte(token),
				jwt.WithKeySet(fresh),
				jwt.WithIssuer(issuerURL),
				jwt.WithValidate(true),
			)
		}
		if err != nil {
			return "", err
		}
	}
	sub := tok.Subject()
	if sub == "" {
		return "", fmt.Errorf("missing sub claim")
	}
	return sub, nil
}

// buildPublicFIT constructs and signs a FIT for the given subject, selecting the
// profile whose audience matches resource. Falls back to the public profile.
func buildPublicFIT(cfg *config.Config, ks *keys.KeyStore, reg *profiles.Registry, sub, resource string) (string, error) {
	pub := reg.ForResource(resource)
	validity := pub.ValidityDays
	if validity == 0 {
		validity = cfg.DefaultValidityDays
	}
	aud := pub.Audience
	if len(aud) == 0 {
		aud = cfg.Audience
	}
	now := time.Now()
	c := tokens.FITClaims{
		ISS:                      cfg.IssuerURL,
		SUB:                      sub,
		AUD:                      aud,
		IAT:                      now.Unix(),
		NBF:                      now.Unix(),
		EXP:                      now.Add(time.Duration(validity) * 24 * time.Hour).Unix(),
		InvestigationID:          tokens.PublicInvestigationID(sub),
		AuthorizedAnalyst:        sub,
		AuthorizedTools:          pub.AuthorizedTools,
		Purpose:                  pub.Purpose,
		FITVersion:               "1.0",
		InvocationTypesPermitted: pub.InvocationTypesPermitted,
	}
	return tokens.Build(c, ks)
}
