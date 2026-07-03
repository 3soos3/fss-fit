package handlers

import (
	"net/http"

	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/revocation"
)

// Health serves GET /health.
func Health(ks *keys.KeyStore, store *revocation.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ks == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "error", "reason": "signing key not loaded",
			})
			return
		}
		if _, err := store.IsRevoked("__healthcheck__", "A"); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "error", "reason": "revocation store unavailable",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
