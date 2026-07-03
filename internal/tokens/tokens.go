package tokens

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/3soos3/fit-issuer/internal/keys"
)

// FITClaims holds all fields for a Forensic Investigation Token.
type FITClaims struct {
	// JWT registered claims
	JTI string
	ISS string
	SUB string
	AUD []string
	IAT int64
	NBF int64
	EXP int64
	// FSS-0006 forensic claims
	InvestigationID          string
	AuthorizedAnalyst        string
	AuthorizedTools          []string
	LegalAuthority           string
	Purpose                  string
	FITVersion               string
	// Optional
	DataScope                string
	InvocationTypesPermitted []string
	Supervisor               string
	Classification           string
}

// Build constructs and signs a FIT as a JWS Compact Serialization string.
// JOSE header: alg=EdDSA, kid=ks.KID(), typ=FIT+JWT.
func Build(c FITClaims, ks *keys.KeyStore) (string, error) {
	if c.JTI == "" {
		c.JTI = uuid.New().String()
	}
	if c.IAT == 0 {
		c.IAT = time.Now().Unix()
	}
	if c.NBF == 0 {
		c.NBF = c.IAT
	}

	tok := jwt.New()
	_ = tok.Set(jwt.JwtIDKey, c.JTI)
	_ = tok.Set(jwt.IssuerKey, c.ISS)
	_ = tok.Set(jwt.AudienceKey, c.AUD)
	_ = tok.Set(jwt.IssuedAtKey, time.Unix(c.IAT, 0))
	_ = tok.Set(jwt.NotBeforeKey, time.Unix(c.NBF, 0))
	_ = tok.Set(jwt.ExpirationKey, time.Unix(c.EXP, 0))
	if c.SUB != "" {
		_ = tok.Set(jwt.SubjectKey, c.SUB)
	}
	_ = tok.Set("investigation_id", c.InvestigationID)
	_ = tok.Set("authorized_analyst", c.AuthorizedAnalyst)
	_ = tok.Set("authorized_tools", c.AuthorizedTools)
	_ = tok.Set("legal_authority", c.LegalAuthority)
	_ = tok.Set("purpose", c.Purpose)
	if c.FITVersion != "" {
		_ = tok.Set("fit_version", c.FITVersion)
	}
	if c.DataScope != "" {
		_ = tok.Set("data_scope", c.DataScope)
	}
	if len(c.InvocationTypesPermitted) > 0 {
		_ = tok.Set("invocation_types_permitted", c.InvocationTypesPermitted)
	}
	if c.Supervisor != "" {
		_ = tok.Set("supervisor", c.Supervisor)
	}
	if c.Classification != "" {
		_ = tok.Set("classification", c.Classification)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.TypeKey, "FIT+JWT"); err != nil {
		return "", fmt.Errorf("set typ: %w", err)
	}
	if err := hdrs.Set(jws.KeyIDKey, ks.KID()); err != nil {
		return "", fmt.Errorf("set kid: %w", err)
	}

	signed, err := jwt.Sign(tok,
		jwt.WithKey(jwa.EdDSA, ks.Private(), jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		return "", fmt.Errorf("sign FIT: %w", err)
	}
	return string(signed), nil
}

// PublicInvestigationID returns "public-" + first 16 hex chars of SHA-256(sub).
func PublicInvestigationID(sub string) string {
	h := sha256.Sum256([]byte(sub))
	return "public-" + hex.EncodeToString(h[:])[:16]
}
