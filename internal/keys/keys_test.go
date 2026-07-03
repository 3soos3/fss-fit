package keys_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/3soos3/fit-issuer/internal/keys"
)

func TestLoadOrGenerate(t *testing.T) {
	dir := t.TempDir()
	ks, err := keys.LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if ks.KID() == "" {
		t.Error("kid should not be empty")
	}
	// PEM round-trip: second load returns same key
	ks2, err := keys.LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerate: %v", err)
	}
	if ks.PublicKeyBase64() != ks2.PublicKeyBase64() {
		t.Error("PEM round-trip: public keys differ")
	}
	if ks.KID() != ks2.KID() {
		t.Error("PEM round-trip: kids differ")
	}
	if _, err := os.Stat(filepath.Join(dir, "signing_key.pem")); err != nil {
		t.Errorf("signing_key.pem not created: %v", err)
	}
}

func TestThumbprintKnownAnswer(t *testing.T) {
	// FSS-0005 Appendix A.2 test key
	// x = "OOA1tQAl3s5MirqjM5PjEBv5H2mmJqeTVrM9F4C6Fr8"
	// expected kid = "6_LIAQcCekpjoV052LAGqjH1nfCkgcCjyOheU9SqVOg"
	xBytes, err := base64.RawURLEncoding.DecodeString("OOA1tQAl3s5MirqjM5PjEBv5H2mmJqeTVrM9F4C6Fr8")
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	pub := ed25519.PublicKey(xBytes)
	kid, err := keys.Thumbprint(pub)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	const want = "6_LIAQcCekpjoV052LAGqjH1nfCkgcCjyOheU9SqVOg"
	if kid != want {
		t.Errorf("kid = %q, want %q", kid, want)
	}
}

func TestJWKS(t *testing.T) {
	dir := t.TempDir()
	ks, err := keys.LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	data, err := ks.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.Keys))
	}
	k := doc.Keys[0]
	for _, field := range []string{"kty", "crv", "kid", "x", "use"} {
		if k[field] == "" {
			t.Errorf("JWKS missing field %q", field)
		}
	}
	if k["kty"] != "OKP"    { t.Errorf("kty = %q, want OKP", k["kty"]) }
	if k["crv"] != "Ed25519" { t.Errorf("crv = %q, want Ed25519", k["crv"]) }
	if k["use"] != "sig"    { t.Errorf("use = %q, want sig", k["use"]) }
	if k["kid"] != ks.KID() { t.Errorf("kid mismatch in JWKS") }
}
