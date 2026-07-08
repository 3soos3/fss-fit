package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/profiles"
	"github.com/3soos3/fit-issuer/internal/tokens"
	"github.com/3soos3/fit-issuer/internal/toolmatch"
)

// Issue handles POST /fit/issue: forensic authority manual FIT issuance.
func Issue(cfg *config.Config, ks *keys.KeyStore, reg *profiles.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bearerToken(r) != cfg.AuthorityToken {
			errJSON(w, http.StatusUnauthorized, "invalid authority token")
			return
		}

		var req profiles.IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		if req.Profile != "" {
			p, ok := reg.Get(req.Profile)
			if !ok {
				errJSON(w, http.StatusBadRequest, "unknown profile: "+req.Profile)
				return
			}
			merged := profiles.Merge(p, &req)
			req = *merged
		}

		for _, check := range []struct{ name, val string }{
			{"investigation_id", req.InvestigationID},
			{"authorized_analyst", req.AuthorizedAnalyst},
			{"legal_authority", req.LegalAuthority},
			{"purpose", req.Purpose},
		} {
			if check.val == "" {
				errJSON(w, http.StatusBadRequest, "missing field: "+check.name)
				return
			}
		}
		if len(req.AuthorizedTools) == 0 {
			errJSON(w, http.StatusBadRequest, "missing field: authorized_tools")
			return
		}
		if err := toolmatch.Validate(req.AuthorizedTools); err != nil {
			errJSON(w, http.StatusBadRequest, err.Error())
			return
		}

		validity := req.ValidDays
		if validity == 0 {
			validity = cfg.DefaultValidityDays
		}
		aud := req.Audience
		if len(aud) == 0 {
			aud = cfg.Audience
		}
		now := time.Now()
		c := tokens.FITClaims{
			ISS:                      cfg.IssuerURL,
			SUB:                      req.AuthorizedAnalyst,
			AUD:                      aud,
			IAT:                      now.Unix(),
			NBF:                      now.Unix(),
			EXP:                      now.Add(time.Duration(validity) * 24 * time.Hour).Unix(),
			InvestigationID:          req.InvestigationID,
			AuthorizedAnalyst:        req.AuthorizedAnalyst,
			AuthorizedTools:          req.AuthorizedTools,
			LegalAuthority:           req.LegalAuthority,
			Purpose:                  req.Purpose,
			DataScope:                req.DataScope,
			InvocationTypesPermitted: req.InvocationTypesPermitted,
			Supervisor:               req.Supervisor,
			Classification:           req.Classification,
			FITVersion:               "1.0",
		}

		compact, err := tokens.Build(c, ks)
		if err != nil {
			slog.Error("build FIT", "err", err)
			errJSON(w, http.StatusInternalServerError, "failed to issue FIT")
			return
		}

		slog.Info("FIT_ISSUED",
			"event", "FIT_ISSUED",
			"issued_by", "authority",
			"investigation_id", c.InvestigationID,
			"authorized_analyst", c.AuthorizedAnalyst,
			"legal_authority", c.LegalAuthority,
		)
		writeJSON(w, http.StatusOK, map[string]string{"fit": compact})
	}
}
