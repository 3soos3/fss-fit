package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/profiles"
	"github.com/3soos3/fit-issuer/internal/tokens"
)

// Login handles POST /fit/login: validates a Dex Bearer JWT and issues a public FIT.
// The OAuth JWKS is fetched lazily on first call and cached; it is re-fetched once
// on signature failure to handle key rotation without requiring a server restart.
func Login(cfg *config.Config, ks *keys.KeyStore, reg *profiles.Registry) http.HandlerFunc {
	var mu sync.Mutex
	var cached jwk.Set

	fetch := func() (jwk.Set, error) {
		return jwk.Fetch(context.Background(), cfg.OAuthJWKSURL)
	}

	getJWKS := func() (jwk.Set, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached == nil {
			var err error
			cached, err = fetch()
			if err != nil {
				return nil, err
			}
		}
		return cached, nil
	}

	refreshJWKS := func() (jwk.Set, error) {
		mu.Lock()
		defer mu.Unlock()
		fresh, err := fetch()
		if err != nil {
			return nil, err
		}
		cached = fresh
		return cached, nil
	}

	return func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerToken(r)
		if bearer == "" {
			errJSON(w, http.StatusUnauthorized, "missing Bearer token")
			return
		}

		jwks, err := getJWKS()
		if err != nil {
			slog.Error("fetch OAuth JWKS", "err", err)
			errJSON(w, http.StatusServiceUnavailable, "OAuth JWKS unavailable")
			return
		}

		dexTok, err := jwt.Parse([]byte(bearer),
			jwt.WithKeySet(jwks),
			jwt.WithIssuer(cfg.OAuthIssuerURL),
			jwt.WithValidate(true),
		)
		if err != nil {
			// Re-fetch once to handle key rotation, then retry
			if fresh, ferr := refreshJWKS(); ferr == nil {
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
