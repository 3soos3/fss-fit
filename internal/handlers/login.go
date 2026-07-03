package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/profiles"
	"github.com/3soos3/fit-issuer/internal/tokens"
)

// Login handles POST /fit/login: validates a Dex Bearer JWT and issues a public FIT.
func Login(cfg *config.Config, ks *keys.KeyStore, reg *profiles.Registry, oauthJWKS jwk.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerToken(r)
		if bearer == "" {
			errJSON(w, http.StatusUnauthorized, "missing Bearer token")
			return
		}

		dexTok, err := jwt.Parse([]byte(bearer),
			jwt.WithKeySet(oauthJWKS),
			jwt.WithIssuer(cfg.OAuthIssuerURL),
			jwt.WithValidate(true),
		)
		if err != nil {
			// Retry with fresh JWKS once (key rotation)
			fresh, ferr := jwk.Fetch(context.Background(), cfg.OAuthJWKSURL)
			if ferr == nil {
				dexTok, err = jwt.Parse([]byte(bearer),
					jwt.WithKeySet(fresh),
					jwt.WithIssuer(cfg.OAuthIssuerURL),
					jwt.WithValidate(true),
				)
			}
			if err != nil {
				errJSON(w, http.StatusUnauthorized, "invalid Dex token")
				return
			}
		}

		sub := dexTok.Subject()
		if sub == "" {
			errJSON(w, http.StatusUnauthorized, "missing sub claim")
			return
		}

		pub := reg.Public()
		validity := pub.ValidityDays
		if validity == 0 {
			validity = cfg.DefaultValidityDays
		}
		now := time.Now()

		c := tokens.FITClaims{
			ISS:                      cfg.IssuerURL,
			SUB:                      sub,
			AUD:                      cfg.Audience,
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

		compact, err := tokens.Build(c, ks)
		if err != nil {
			slog.Error("build FIT", "err", err)
			errJSON(w, http.StatusInternalServerError, "failed to issue FIT")
			return
		}

		slog.Info("FIT_ISSUED",
			"event", "FIT_ISSUED",
			"issued_by", "public-login",
			"investigation_id", c.InvestigationID,
			"authorized_analyst", c.AuthorizedAnalyst,
		)
		writeJSON(w, http.StatusOK, map[string]string{"fit": compact})
	}
}
