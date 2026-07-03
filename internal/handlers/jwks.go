package handlers

import (
	"net/http"

	"github.com/3soos3/fit-issuer/internal/keys"
)

// JWKS serves GET /.well-known/fss-jwks.json.
func JWKS(ks *keys.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := ks.JWKS()
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}
