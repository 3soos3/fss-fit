package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/revocation"
	"github.com/3soos3/fit-issuer/internal/toolmatch"
)

// fitClaims holds the raw JWT payload fields we need for verification.
// aud can be a string or []string in the wire format; we handle both.
type fitClaims struct {
	JTI                      string          `json:"jti"`
	ISS                      string          `json:"iss"`
	AUD                      json.RawMessage `json:"aud"`
	IAT                      int64           `json:"iat"`
	NBF                      int64           `json:"nbf"`
	EXP                      int64           `json:"exp"`
	InvestigationID          string          `json:"investigation_id"`
	AuthorizedAnalyst        string          `json:"authorized_analyst"`
	AuthorizedTools          []string        `json:"authorized_tools"`
	LegalAuthority           string          `json:"legal_authority"`
	Purpose                  string          `json:"purpose"`
	InvocationTypesPermitted []string        `json:"invocation_types_permitted"`
}

func (c *fitClaims) audSlice() []string {
	if len(c.AUD) == 0 {
		return nil
	}
	// Try array first
	var arr []string
	if json.Unmarshal(c.AUD, &arr) == nil {
		return arr
	}
	// Fall back to single string
	var s string
	if json.Unmarshal(c.AUD, &s) == nil {
		return []string{s}
	}
	return nil
}

func (c *fitClaims) audContains(target string) bool {
	for _, a := range c.audSlice() {
		if a == target {
			return true
		}
	}
	return false
}

type verifyRequest struct {
	FIT             string `json:"fit"`
	ToolName        string `json:"tool_name"`
	ServerID        string `json:"server_id"`
	InvestigationID string `json:"investigation_id"`
	ClientIdentity  string `json:"client_identity"`
	InvocationType  string `json:"invocation_type"`
	ServerProfile   string `json:"server_profile"`
}

type verifyFailure struct {
	Valid      bool   `json:"valid"`
	FailedStep int    `json:"failed_step"`
	Reason     string `json:"reason"`
}

type verifySuccess struct {
	Valid                     bool     `json:"valid"`
	FitJTI                    string   `json:"fit_jti"`
	FitIssuer                 string   `json:"fit_issuer"`
	FitValidUntil             string   `json:"fit_valid_until"`
	FitAud                    []string `json:"fit_aud"`
	LegalAuthority            string   `json:"legal_authority"`
	Purpose                   string   `json:"purpose"`
	InvestigationIDVerified   bool     `json:"investigation_id_verified"`
	ToolAuthorizationVerified bool     `json:"tool_authorization_verified"`
}

// Verify handles POST /fit/verify: runs the 11-step FSS-0006 §8.2 procedure.
func Verify(cfg *config.Config, ks *keys.KeyStore, store *revocation.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req verifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.ServerProfile == "" {
			req.ServerProfile = "A"
		}

		fail := func(step int, reason string) {
			slog.Info("FSS_AUTH_DENIED",
				"event", "FSS_AUTH_DENIED",
				"failed_step", step,
				"reason", reason,
			)
			writeJSON(w, http.StatusOK, verifyFailure{
				Valid: false, FailedStep: step, Reason: reason,
			})
		}

		// Parse JOSE header without verifying signature
		msg, err := jws.Parse([]byte(req.FIT))
		if err != nil || len(msg.Signatures()) == 0 {
			fail(1, "malformed JWT")
			return
		}
		hdr := msg.Signatures()[0].ProtectedHeaders()

		// Step 1: typ must be FIT+JWT
		if hdr.Type() != "FIT+JWT" {
			fail(1, "typ must be FIT+JWT")
			return
		}

		// Decode the JWT payload directly from the compact serialization.
		// Using msg.Payload() from jws.Parse can return re-encoded bytes in some
		// library versions; splitting on "." and base64url-decoding is reliable.
		parts := strings.SplitN(req.FIT, ".", 3)
		if len(parts) != 3 {
			fail(1, "malformed JWT: expected 3 parts")
			return
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			fail(1, "malformed JWT payload encoding")
			return
		}
		var claims fitClaims
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			fail(1, "malformed JWT claims")
			return
		}

		// Step 2: issuer must be our own
		if claims.ISS != cfg.IssuerURL {
			fail(2, "untrusted issuer")
			return
		}

		// Step 3: kid must resolve in our JWKS
		if hdr.KeyID() != ks.KID() {
			fail(3, "unknown kid")
			return
		}

		// Step 4: signature must be valid
		if _, err := jws.Verify([]byte(req.FIT), jws.WithKey(jwa.EdDSA, ks.PublicKey())); err != nil {
			fail(4, "invalid signature")
			return
		}

		// Step 5: aud must include server_id
		if !claims.audContains(req.ServerID) {
			fail(5, "aud does not include server_id")
			return
		}

		// Step 6: revocation check (profile-based TTL)
		revoked, err := store.IsRevoked(claims.JTI, req.ServerProfile)
		if err != nil {
			fail(6, "revocation check failed")
			return
		}
		if revoked {
			fail(6, "token revoked")
			return
		}

		// Step 7: time window with 30s clock skew tolerance
		now := time.Now().Unix()
		skew := int64(30)
		if now < claims.NBF-skew {
			fail(7, "token not yet valid")
			return
		}
		if now > claims.EXP+skew {
			fail(7, "token expired")
			return
		}

		// Step 8: investigation_id must match
		if claims.InvestigationID != req.InvestigationID {
			fail(8, "investigation_id mismatch")
			return
		}

		// Step 9: tool must be in authorized_tools
		if !toolmatch.Match(claims.AuthorizedTools, req.ToolName) {
			fail(9, "tool not authorized")
			return
		}

		// Step 10: client_identity must match authorized_analyst
		if claims.AuthorizedAnalyst != req.ClientIdentity {
			fail(10, "client_identity mismatch")
			return
		}

		// Step 11: invocation_type check (conditional)
		if len(claims.InvocationTypesPermitted) > 0 {
			found := false
			for _, t := range claims.InvocationTypesPermitted {
				if t == req.InvocationType {
					found = true
					break
				}
			}
			if !found {
				fail(11, "invocation_type not permitted")
				return
			}
		}

		writeJSON(w, http.StatusOK, verifySuccess{
			Valid:                     true,
			FitJTI:                    claims.JTI,
			FitIssuer:                 claims.ISS,
			FitValidUntil:             time.Unix(claims.EXP, 0).UTC().Format(time.RFC3339),
			FitAud:                    claims.audSlice(),
			LegalAuthority:            claims.LegalAuthority,
			Purpose:                   claims.Purpose,
			InvestigationIDVerified:   true,
			ToolAuthorizationVerified: true,
		})
	}
}

