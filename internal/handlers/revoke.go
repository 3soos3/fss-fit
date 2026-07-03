package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/revocation"
)

// Revoke handles POST /fit/revoke: revokes a FIT by jti.
func Revoke(cfg *config.Config, store *revocation.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bearerToken(r) != cfg.AuthorityToken {
			errJSON(w, http.StatusUnauthorized, "invalid authority token")
			return
		}

		var body struct {
			JTI       string `json:"jti"`
			Reason    string `json:"reason"`
			RevokedBy string `json:"revoked_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if _, err := uuid.Parse(body.JTI); err != nil {
			errJSON(w, http.StatusBadRequest, "jti must be UUID v4")
			return
		}
		if body.Reason == "" {
			errJSON(w, http.StatusBadRequest, "reason is required")
			return
		}
		revokedBy := body.RevokedBy
		if revokedBy == "" {
			revokedBy = "authority"
		}

		e := revocation.Entry{
			JTI:              body.JTI,
			ISS:              cfg.IssuerURL,
			RevokedAt:        time.Now().UTC().Format(time.RFC3339),
			RevocationReason: body.Reason,
			RevokedBy:        revokedBy,
		}
		if err := store.Revoke(e); err != nil {
			slog.Error("revoke failed", "err", err)
			errJSON(w, http.StatusInternalServerError, "revoke failed")
			return
		}

		slog.Info("FIT_REVOKED",
			"event", "FIT_REVOKED",
			"jti", body.JTI,
			"reason", body.Reason,
			"revoked_at", e.RevokedAt,
		)
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	}
}
