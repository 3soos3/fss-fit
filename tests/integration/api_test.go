package integration_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/handlers"
	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/profiles"
	"github.com/3soos3/fit-issuer/internal/revocation"
	"github.com/3soos3/fit-issuer/internal/tokens"
)

// FSS-0006 Appendix A.2 test vectors. The test server uses the FSS-0005 A.2 key.
const (
	testServerID = "https://mcp.example.org/solve-it"
	testIssuer   = "https://casemanagement.example.org/fss"
	testInvID    = "550e8400-e29b-41d4-a716-446655440000"
	testAnalyst  = "analyst@example.org"
	testJTI      = "770a0600-e29b-41d4-a716-446655440002"
	testTool     = "search_technique"
	authToken    = "test-authority-token-secret"

	vectorA_valid          = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1NDA0MjQwMCwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiaXNzIjoiaHR0cHM6Ly9jYXNlbWFuYWdlbWVudC5leGFtcGxlLm9yZy9mc3MiLCJqdGkiOiI3NzBhMDYwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDIiLCJsZWdhbF9hdXRob3JpdHkiOiJDQVNFLTIwMjYtMDA0MiIsIm5iZiI6MTc1MTQ1MDQwMCwicHVycG9zZSI6IklkZW50aWZ5IG1hbHdhcmUgcGVyc2lzdGVuY2UgdGVjaG5pcXVlcyB1c2VkIGluIGNhc2UgQ0FTRS0yMDI2LTAwNDIifQ.8MgK42_wQ6mQVQsReE0m_28rM0T1ODe4VJgzmyVsSs1TIIzUJyuQqQLqhrzmN3g9pFVYlfvnPIgbfTtDyPTuAg"
	vectorB_wrongAud       = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL290aGVyLXNlcnZlci5leGFtcGxlLm9yZy93cm9uZyIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1NDA0MjQwMCwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiaXNzIjoiaHR0cHM6Ly9jYXNlbWFuYWdlbWVudC5leGFtcGxlLm9yZy9mc3MiLCJqdGkiOiI3NzBhMDYwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDIiLCJsZWdhbF9hdXRob3JpdHkiOiJDQVNFLTIwMjYtMDA0MiIsIm5iZiI6MTc1MTQ1MDQwMCwicHVycG9zZSI6IklkZW50aWZ5IG1hbHdhcmUgcGVyc2lzdGVuY2UgdGVjaG5pcXVlcyB1c2VkIGluIGNhc2UgQ0FTRS0yMDI2LTAwNDIifQ.83bKhWMyEy87ECVp4whVvyJQPlisoapR6odoP8rhkDO77J4WdM-oo2jV5NEyoi3_01iBHN_B9hswecH7gU8OBg"
	vectorC_expired        = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1MTQ1MDM5OSwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiaXNzIjoiaHR0cHM6Ly9jYXNlbWFuYWdlbWVudC5leGFtcGxlLm9yZy9mc3MiLCJqdGkiOiI3NzBhMDYwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDIiLCJsZWdhbF9hdXRob3JpdHkiOiJDQVNFLTIwMjYtMDA0MiIsIm5iZiI6MTc1MTQ1MDQwMCwicHVycG9zZSI6IklkZW50aWZ5IG1hbHdhcmUgcGVyc2lzdGVuY2UgdGVjaG5pcXVlcyB1c2VkIGluIGNhc2UgQ0FTRS0yMDI2LTAwNDIifQ.FokIy1pz4IEn8_nLQLUOzx1ZNkPmZMHmKRA4jGm4ur81fxGTB8pKRZ-qH06ggFaRgy3MmwGHttydSFOxP5F5BQ"
	vectorE_badSig         = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1NDA0MjQwMCwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiaXNzIjoiaHR0cHM6Ly9jYXNlbWFuYWdlbWVudC5leGFtcGxlLm9yZy9mc3MiLCJqdGkiOiI3NzBhMDYwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDIiLCJsZWdhbF9hdXRob3JpdHkiOiJDQVNFLTIwMjYtMDA0MiIsIm5iZiI6MTc1MTQ1MDQwMCwicHVycG9zZSI6IklkZW50aWZ5IG1hbHdhcmUgcGVyc2lzdGVuY2UgdGVjaG5pcXVlcyB1c2VkIGluIGNhc2UgQ0FTRS0yMDI2LTAwNDIifQ.8cgK42_wQ6mQVQsReE0m_28rM0T1ODe4VJgzmyVsSs1TIIzUJyuQqQLqhrzmN3g9pFVYlfvnPIgbfTtDyPTuAg"
	vectorG_untrustedIss   = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1NDA0MjQwMCwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiaXNzIjoiaHR0cHM6Ly91bnRydXN0ZWQtYXV0aG9yaXR5LmV4YW1wbGUub3JnL2ZzcyIsImp0aSI6Ijc3MGEwNjAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMiIsImxlZ2FsX2F1dGhvcml0eSI6IkNBU0UtMjAyNi0wMDQyIiwibmJmIjoxNzUxNDUwNDAwLCJwdXJwb3NlIjoiSWRlbnRpZnkgbWFsd2FyZSBwZXJzaXN0ZW5jZSB0ZWNobmlxdWVzIHVzZWQgaW4gY2FzZSBDQVNFLTIwMjYtMDA0MiJ9.0NWmGP4D1xcuw__ZZQgJgzVB9ZgCH0OhTtOlc69J5rLNiRzNLuNZnJlep19_pzZ_mxvaPy9KHkdezc4VUxMZDQ"
	vectorH_notYetValid    = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1NDA0NjAwMCwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiaXNzIjoiaHR0cHM6Ly9jYXNlbWFuYWdlbWVudC5leGFtcGxlLm9yZy9mc3MiLCJqdGkiOiI3NzBhMDYwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDIiLCJsZWdhbF9hdXRob3JpdHkiOiJDQVNFLTIwMjYtMDA0MiIsIm5iZiI6MTc1MTQ1NDAwMCwicHVycG9zZSI6IklkZW50aWZ5IG1hbHdhcmUgcGVyc2lzdGVuY2UgdGVjaG5pcXVlcyB1c2VkIGluIGNhc2UgQ0FTRS0yMDI2LTAwNDIifQ.GyqpfOwf5ffyvlHewS9W7d2CQq5-FazVGv7na3wf_-mBDyQbfzyioJ4sUM2vIL147ZWAQpPbptzcrydJW08QCQ"
	vectorI_invIDMismatch  = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1NDA0MjQwMCwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiYWFhYWFhYWEtYmJiYi00Y2NjLThkZGQtZWVlZWVlZWVlZWVlIiwiaXNzIjoiaHR0cHM6Ly9jYXNlbWFuYWdlbWVudC5leGFtcGxlLm9yZy9mc3MiLCJqdGkiOiI3NzBhMDYwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDIiLCJsZWdhbF9hdXRob3JpdHkiOiJDQVNFLTIwMjYtMDA0MiIsIm5iZiI6MTc1MTQ1MDQwMCwicHVycG9zZSI6IklkZW50aWZ5IG1hbHdhcmUgcGVyc2lzdGVuY2UgdGVjaG5pcXVlcyB1c2VkIGluIGNhc2UgQ0FTRS0yMDI2LTAwNDIifQ.9J8czWOqsVInXTc6SFwJrVq5s5d4fjP-fjfl17nZ3zdnbOIsyHMQa7fUdxFSDMUqnHlU58g8il-L3W_pBREXCQ"
	vectorJ_analystMismatch = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImRpZmZlcmVudC1hbmFseXN0QGV4YW1wbGUub3JnIiwiYXV0aG9yaXplZF90b29scyI6WyJzZWFyY2hfdGVjaG5pcXVlIiwiZ2V0X3RlY2huaXF1ZSJdLCJleHAiOjE3NTQwNDI0MDAsImlhdCI6MTc1MTQ1MDQwMCwiaW52ZXN0aWdhdGlvbl9pZCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCIsImlzcyI6Imh0dHBzOi8vY2FzZW1hbmFnZW1lbnQuZXhhbXBsZS5vcmcvZnNzIiwianRpIjoiNzcwYTA2MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAyIiwibGVnYWxfYXV0aG9yaXR5IjoiQ0FTRS0yMDI2LTAwNDIiLCJuYmYiOjE3NTE0NTA0MDAsInB1cnBvc2UiOiJJZGVudGlmeSBtYWx3YXJlIHBlcnNpc3RlbmNlIHRlY2huaXF1ZXMgdXNlZCBpbiBjYXNlIENBU0UtMjAyNi0wMDQyIn0.yM4x4qAUU2HHtcwgf76FtRzyuODR4IghNFfy5gDlGnhg3Q3uCqqPXiMkRpPApPjsVyp0Jm1OiKWkO71lHergAA"
	vectorK_invocationType  = "eyJhbGciOiJFZERTQSIsImtpZCI6IjZfTElBUWNDZWtwam9WMDUyTEFHcWpIMW5mQ2tnY0NqeU9oZVU5U3FWT2ciLCJ0eXAiOiJGSVQrSldUIn0.eyJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLm9yZy9zb2x2ZS1pdCIsImF1dGhvcml6ZWRfYW5hbHlzdCI6ImFuYWx5c3RAZXhhbXBsZS5vcmciLCJhdXRob3JpemVkX3Rvb2xzIjpbInNlYXJjaF90ZWNobmlxdWUiLCJnZXRfdGVjaG5pcXVlIl0sImV4cCI6MTc1NDA0MjQwMCwiaWF0IjoxNzUxNDUwNDAwLCJpbnZlc3RpZ2F0aW9uX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiaW52b2NhdGlvbl90eXBlc19wZXJtaXR0ZWQiOlsiaHVtYW5fZGlyZWN0Il0sImlzcyI6Imh0dHBzOi8vY2FzZW1hbmFnZW1lbnQuZXhhbXBsZS5vcmcvZnNzIiwianRpIjoiNzcwYTA2MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAyIiwibGVnYWxfYXV0aG9yaXR5IjoiQ0FTRS0yMDI2LTAwNDIiLCJuYmYiOjE3NTE0NTA0MDAsInB1cnBvc2UiOiJJZGVudGlmeSBtYWx3YXJlIHBlcnNpc3RlbmNlIHRlY2huaXF1ZXMgdXNlZCBpbiBjYXNlIENBU0UtMjAyNi0wMDQyIn0.AKO4gZ-mWQW0EnSQtFsiMk5goq18XAb_AL-aFLTCD1T-JJDZKPY96-Jz3D9qjU5gJT9CYVBmBOUK95iVIX-KBA"
)

// testEnv holds per-test server state.
type testEnv struct {
	srv      *httptest.Server
	cfg      *config.Config
	ks       *keys.KeyStore
	dexPub   ed25519.PublicKey
	dexPriv  ed25519.PrivateKey
	dexIssURL string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Load the FSS-0005 Appendix A.2 test key as the fit-issuer signing key
	rawJWK := []byte(`{"kty":"OKP","crv":"Ed25519","kid":"6_LIAQcCekpjoV052LAGqjH1nfCkgcCjyOheU9SqVOg","x":"OOA1tQAl3s5MirqjM5PjEBv5H2mmJqeTVrM9F4C6Fr8","d":"9QPM8OS1OIPdFfsJ9DXp_GGZ7r1io6W02HO7Qh2ay5s"}`)
	k, err := jwk.ParseKey(rawJWK)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	var fitPriv ed25519.PrivateKey
	if err := k.Raw(&fitPriv); err != nil {
		t.Fatalf("raw test key: %v", err)
	}
	ks, err := keys.NewFromRaw(fitPriv)
	if err != nil {
		t.Fatalf("NewFromRaw: %v", err)
	}

	// Generate mock Dex keypair
	dexPub, dexPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate dex key: %v", err)
	}

	// Serve mock Dex JWKS
	dexJWKS, err := buildJWKS(dexPub)
	if err != nil {
		t.Fatalf("build dex JWKS: %v", err)
	}
	dexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(dexJWKS)
	}))
	t.Cleanup(dexSrv.Close)

	dexIssURL := dexSrv.URL
	dataDir := t.TempDir()

	store, err := revocation.New(dataDir)
	if err != nil {
		t.Fatalf("revocation.New: %v", err)
	}

	// Build the JWKS set programmatically to avoid jwk.Fetch + OKP key matching issues
	dexKID, err := keys.Thumbprint(dexPub)
	if err != nil {
		t.Fatalf("dex thumbprint: %v", err)
	}
	dexPubJWK, err := jwk.FromRaw(dexPub)
	if err != nil {
		t.Fatalf("jwk from raw dex pub: %v", err)
	}
	_ = dexPubJWK.Set(jwk.KeyIDKey, dexKID)
	_ = dexPubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA)
	oauthJWKS := jwk.NewSet()
	_ = oauthJWKS.AddKey(dexPubJWK)

	// Use testIssuer as FIT_ISSUER_URL so FSS-0006 vectors' iss matches
	cfg := &config.Config{
		IssuerURL:           testIssuer,
		JWKSURL:             "https://fit.example.org/.well-known/fss-jwks.json",
		OAuthJWKSURL:        dexSrv.URL,
		OAuthIssuerURL:      dexIssURL,
		Audience:            []string{testServerID},
		DefaultValidityDays: 30,
		AuthorityToken:      authToken,
		DataDir:             dataDir,
		ProfilesConfig:      dataDir + "/profiles.yaml",
	}

	reg, err := profiles.Load(cfg.ProfilesConfig)
	if err != nil {
		t.Fatalf("profiles.Load: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/fss-jwks.json", handlers.JWKS(ks))
	mux.HandleFunc("GET /health", handlers.Health(ks, store))
	mux.HandleFunc("POST /fit/login", handlers.Login(cfg, ks, reg, oauthJWKS))
	mux.HandleFunc("POST /fit/issue", handlers.Issue(cfg, ks, reg))
	mux.HandleFunc("POST /fit/revoke", handlers.Revoke(cfg, store))
	mux.HandleFunc("POST /fit/verify", handlers.Verify(cfg, ks, store))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testEnv{
		srv: srv, cfg: cfg, ks: ks,
		dexPub: dexPub, dexPriv: dexPriv, dexIssURL: dexIssURL,
	}
}

func buildJWKS(pub ed25519.PublicKey) ([]byte, error) {
	kid, err := keys.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	doc := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": kid,
				"x":   base64.RawURLEncoding.EncodeToString(pub),
				"use": "sig",
			},
		},
	}
	return json.Marshal(doc)
}

func (e *testEnv) makeDexJWT(sub string, exp time.Time) string {
	tok := jwt.New()
	_ = tok.Set(jwt.SubjectKey, sub)
	_ = tok.Set(jwt.IssuerKey, e.dexIssURL)
	_ = tok.Set(jwt.IssuedAtKey, time.Now())
	_ = tok.Set(jwt.ExpirationKey, exp)

	// Compute kid so the JWT header matches the JWKS entry
	dexKID, err := keys.Thumbprint(e.dexPub)
	if err != nil {
		panic(fmt.Sprintf("dex thumbprint: %v", err))
	}
	// Sign with raw private key and an explicit kid header
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, dexKID); err != nil {
		panic(fmt.Sprintf("set kid header: %v", err))
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, e.dexPriv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		panic(fmt.Sprintf("sign dex JWT: %v", err))
	}
	return string(signed)
}

func (e *testEnv) post(t *testing.T, path string, body any, authHeader string) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (e *testEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// issueFIT issues a FIT via POST /fit/issue and returns the compact JWT.
func (e *testEnv) issueFIT(t *testing.T, invID, analyst, tool string) string {
	t.Helper()
	return e.issueFITFull(t, invID, analyst, []string{tool}, nil)
}

// issueFITFull issues a FIT with optional invocation_types_permitted.
func (e *testEnv) issueFITFull(t *testing.T, invID, analyst string, tools []string, invTypes []string) string {
	t.Helper()
	body := map[string]interface{}{
		"investigation_id":   invID,
		"authorized_analyst": analyst,
		"authorized_tools":   tools,
		"legal_authority":    "CASE-TEST-001",
		"purpose":            "integration test",
	}
	if len(invTypes) > 0 {
		body["invocation_types_permitted"] = invTypes
	}
	resp := e.post(t, "/fit/issue", body, "Bearer "+authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue FIT: status %d", resp.StatusCode)
	}
	var out map[string]string
	decode(t, resp, &out)
	return out["fit"]
}

type verifyResult struct {
	Valid      bool   `json:"valid"`
	FailedStep int    `json:"failed_step"`
	Reason     string `json:"reason"`
}

func (e *testEnv) verify(t *testing.T, fit, tool, serverID, invID, client, invType string) verifyResult {
	t.Helper()
	body := map[string]string{
		"fit":              fit,
		"tool_name":        tool,
		"server_id":        serverID,
		"investigation_id": invID,
		"client_identity":  client,
		"invocation_type":  invType,
	}
	resp := e.post(t, "/fit/verify", body, "")
	var out verifyResult
	decode(t, resp, &out)
	return out
}

// --- Tests ---

func TestHealth(t *testing.T) {
	e := newTestEnv(t)
	resp := e.get(t, "/health")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health: status %d", resp.StatusCode)
	}
	var out map[string]string
	decode(t, resp, &out)
	if out["status"] != "ok" {
		t.Errorf("health status = %q, want ok", out["status"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	e := newTestEnv(t)
	resp := e.get(t, "/.well-known/fss-jwks.json")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("JWKS: status %d", resp.StatusCode)
	}
	var out struct {
		Keys []map[string]string `json:"keys"`
	}
	decode(t, resp, &out)
	if len(out.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(out.Keys))
	}
	if out.Keys[0]["kid"] != e.ks.KID() {
		t.Errorf("kid mismatch")
	}
}

func TestLoginValid(t *testing.T) {
	e := newTestEnv(t)
	bearer := e.makeDexJWT("user@example.org", time.Now().Add(time.Hour))
	resp := e.post(t, "/fit/login", nil, "Bearer "+bearer)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
	var out map[string]string
	decode(t, resp, &out)
	if out["fit"] == "" {
		t.Error("expected fit in response")
	}
}

func TestLoginExpiredDex(t *testing.T) {
	e := newTestEnv(t)
	bearer := e.makeDexJWT("user@example.org", time.Now().Add(-time.Hour))
	resp := e.post(t, "/fit/login", nil, "Bearer "+bearer)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired dex: want 401, got %d", resp.StatusCode)
	}
}

func TestLoginNoBearerToken(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, "/fit/login", nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no bearer: want 401, got %d", resp.StatusCode)
	}
}

func TestIssueValid(t *testing.T) {
	e := newTestEnv(t)
	fit := e.issueFIT(t, testInvID, testAnalyst, testTool)
	if fit == "" {
		t.Error("expected non-empty FIT")
	}
}

func TestIssueMissingField(t *testing.T) {
	e := newTestEnv(t)
	body := map[string]interface{}{
		"authorized_analyst": testAnalyst,
		"authorized_tools":   []string{testTool},
		"legal_authority":    "CASE-001",
		"purpose":            "test",
		// investigation_id missing
	}
	resp := e.post(t, "/fit/issue", body, "Bearer "+authToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing field: want 400, got %d", resp.StatusCode)
	}
}

func TestIssueCatchAllPattern(t *testing.T) {
	e := newTestEnv(t)
	body := map[string]interface{}{
		"investigation_id":   testInvID,
		"authorized_analyst": testAnalyst,
		"authorized_tools":   []string{".*"},
		"legal_authority":    "CASE-001",
		"purpose":            "test",
	}
	resp := e.post(t, "/fit/issue", body, "Bearer "+authToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("catch-all: want 400, got %d", resp.StatusCode)
	}
}

func TestIssueInvalidRegexp(t *testing.T) {
	e := newTestEnv(t)
	body := map[string]interface{}{
		"investigation_id":   testInvID,
		"authorized_analyst": testAnalyst,
		"authorized_tools":   []string{"[unclosed"},
		"legal_authority":    "CASE-001",
		"purpose":            "test",
	}
	resp := e.post(t, "/fit/issue", body, "Bearer "+authToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid regexp: want 400, got %d", resp.StatusCode)
	}
}

func TestIssueValidPattern(t *testing.T) {
	e := newTestEnv(t)
	body := map[string]interface{}{
		"investigation_id":   testInvID,
		"authorized_analyst": testAnalyst,
		"authorized_tools":   []string{"search_.*"},
		"legal_authority":    "CASE-001",
		"purpose":            "test",
	}
	resp := e.post(t, "/fit/issue", body, "Bearer "+authToken)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid pattern: want 200, got %d", resp.StatusCode)
	}
}

func TestIssueWrongToken(t *testing.T) {
	e := newTestEnv(t)
	body := map[string]interface{}{
		"investigation_id":   testInvID,
		"authorized_analyst": testAnalyst,
		"authorized_tools":   []string{testTool},
		"legal_authority":    "CASE-001",
		"purpose":            "test",
	}
	resp := e.post(t, "/fit/issue", body, "Bearer wrong-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: want 401, got %d", resp.StatusCode)
	}
}

func TestRevokeAndVerify(t *testing.T) {
	e := newTestEnv(t)
	fit := e.issueFIT(t, testInvID, testAnalyst, testTool)

	// Parse the jti out of the issued FIT
	tok, err := jwt.ParseInsecure([]byte(fit))
	if err != nil {
		t.Fatalf("parse FIT: %v", err)
	}
	jti := tok.JwtID()

	// Revoke it
	revokeBody := map[string]string{"jti": jti, "reason": "test revocation"}
	resp := e.post(t, "/fit/revoke", revokeBody, "Bearer "+authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: status %d", resp.StatusCode)
	}

	// Verify should now fail at step 6
	result := e.verify(t, fit, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.Valid {
		t.Error("expected invalid after revocation")
	}
	if result.FailedStep != 6 {
		t.Errorf("expected failed_step=6, got %d", result.FailedStep)
	}
}

func TestRevokeRecordFormat(t *testing.T) {
	e := newTestEnv(t)
	fit := e.issueFIT(t, testInvID, testAnalyst, testTool)
	tok, _ := jwt.ParseInsecure([]byte(fit))
	jti := tok.JwtID()

	revokeBody := map[string]string{
		"jti":        jti,
		"reason":     "test",
		"revoked_by": "integration-test",
	}
	resp := e.post(t, "/fit/revoke", revokeBody, "Bearer "+authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: status %d", resp.StatusCode)
	}

	data, err := os.ReadFile(e.cfg.DataDir + "/revoked_jtis.json")
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var entries []map[string]string
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry["jti"] == jti {
			found = true
			if entry["iss"] == ""               { t.Error("iss empty") }
			if entry["revoked_at"] == ""         { t.Error("revoked_at empty") }
			if entry["revocation_reason"] == ""  { t.Error("revocation_reason empty") }
			if entry["revoked_by"] == ""         { t.Error("revoked_by empty") }
		}
	}
	if !found {
		t.Errorf("jti %s not found in revoked_jtis.json", jti)
	}
}

// --- FSS-0006 Appendix A.2 vector tests ---
// These require the server to be configured with FIT_ISSUER_URL = testIssuer
// (set in newTestEnv).

func TestVerifyAllStepsPass(t *testing.T) {
	// Issue a fresh FIT (vectors expire in 2026; use a live issuance instead)
	e := newTestEnv(t)
	fit := e.issueFIT(t, testInvID, testAnalyst, testTool)
	result := e.verify(t, fit, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if !result.Valid {
		t.Errorf("expected valid=true, got failed_step=%d reason=%s", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep2UntrustedIss(t *testing.T) {
	e := newTestEnv(t)
	result := e.verify(t, vectorG_untrustedIss, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 2 {
		t.Errorf("expected failed_step=2, got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep4BadSig(t *testing.T) {
	e := newTestEnv(t)
	result := e.verify(t, vectorE_badSig, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 4 {
		t.Errorf("expected failed_step=4, got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep5WrongAud(t *testing.T) {
	e := newTestEnv(t)
	result := e.verify(t, vectorB_wrongAud, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 5 {
		t.Errorf("expected failed_step=5, got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep6Revoked(t *testing.T) {
	e := newTestEnv(t)
	// Revoke testJTI (the jti used in all A.2 vectors)
	revokeBody := map[string]string{"jti": testJTI, "reason": "test"}
	e.post(t, "/fit/revoke", revokeBody, "Bearer "+authToken)
	// vectorA has testJTI and valid sig+aud — should fail at step 6
	result := e.verify(t, vectorA_valid, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 6 {
		t.Errorf("expected failed_step=6, got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep7Expired(t *testing.T) {
	e := newTestEnv(t)
	result := e.verify(t, vectorC_expired, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 7 {
		t.Errorf("expected failed_step=7 (expired), got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep7NotYetValid(t *testing.T) {
	e := newTestEnv(t)
	// Build a fresh FIT with nbf one hour in the future
	now := time.Now().Unix()
	c := tokens.FITClaims{
		ISS:               testIssuer,
		AUD:               []string{testServerID},
		IAT:               now,
		NBF:               now + 3600, // valid 1 hour from now
		EXP:               now + 7200,
		InvestigationID:   testInvID,
		AuthorizedAnalyst: testAnalyst,
		AuthorizedTools:   []string{testTool},
		LegalAuthority:    "CASE-TEST-001",
		Purpose:           "test",
	}
	fit, err := tokens.Build(c, e.ks)
	if err != nil {
		t.Fatalf("build future-nbf FIT: %v", err)
	}
	result := e.verify(t, fit, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 7 {
		t.Errorf("expected failed_step=7 (not yet valid), got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep8InvIDMismatch(t *testing.T) {
	e := newTestEnv(t)
	// Issue FIT for inv-A; verify with inv-B → mismatch at step 8
	fit := e.issueFIT(t, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", testAnalyst, testTool)
	result := e.verify(t, fit, testTool, testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 8 {
		t.Errorf("expected failed_step=8, got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep9ToolNotAuthorized(t *testing.T) {
	e := newTestEnv(t)
	// Issue FIT for get_technique only; verify with search_technique → step 9
	fit := e.issueFIT(t, testInvID, testAnalyst, "get_technique")
	result := e.verify(t, fit, "search_technique", testServerID, testInvID, testAnalyst, "human_direct")
	if result.FailedStep != 9 {
		t.Errorf("expected failed_step=9, got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep10AnalystMismatch(t *testing.T) {
	e := newTestEnv(t)
	// Issue FIT for analyst-A; verify with analyst-B → step 10
	fit := e.issueFIT(t, testInvID, "analyst-a@example.org", testTool)
	result := e.verify(t, fit, testTool, testServerID, testInvID, "analyst-b@example.org", "human_direct")
	if result.FailedStep != 10 {
		t.Errorf("expected failed_step=10, got %d (%s)", result.FailedStep, result.Reason)
	}
}

func TestVerifyStep11InvocationType(t *testing.T) {
	e := newTestEnv(t)
	// Issue FIT allowing only human_direct; verify with agent_supervised → step 11
	fit := e.issueFITFull(t, testInvID, testAnalyst, []string{testTool}, []string{"human_direct"})
	result := e.verify(t, fit, testTool, testServerID, testInvID, testAnalyst, "agent_supervised")
	if result.FailedStep != 11 {
		t.Errorf("expected failed_step=11, got %d (%s)", result.FailedStep, result.Reason)
	}
}
