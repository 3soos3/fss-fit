package keys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// KeyStore holds the active Ed25519 signing key.
type KeyStore struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	kid     string
}

// LoadOrGenerate loads the signing key from dataDir/signing_key.pem,
// generating and persisting a new one if absent.
func LoadOrGenerate(dataDir string) (*KeyStore, error) {
	path := filepath.Join(dataDir, "signing_key.pem")
	var priv ed25519.PrivateKey

	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM in %s", path)
		}
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse signing key: %w", err)
		}
		var ok bool
		priv, ok = raw.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key is not Ed25519")
		}
	} else {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		if err := persistKey(priv, path); err != nil {
			return nil, fmt.Errorf("persist key: %w", err)
		}
	}

	pub := priv.Public().(ed25519.PublicKey)
	kid, err := Thumbprint(pub)
	if err != nil {
		return nil, fmt.Errorf("thumbprint: %w", err)
	}
	ks := &KeyStore{private: priv, public: pub, kid: kid}
	slog.Info("signing key loaded",
		"kid", kid,
		"public_key", base64.RawURLEncoding.EncodeToString(pub),
	)
	return ks, nil
}

// NewFromRaw creates a KeyStore from an existing private key (for tests).
func NewFromRaw(priv ed25519.PrivateKey) (*KeyStore, error) {
	pub := priv.Public().(ed25519.PublicKey)
	kid, err := Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	return &KeyStore{private: priv, public: pub, kid: kid}, nil
}

func persistKey(priv ed25519.PrivateKey, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// Thumbprint computes the RFC 7638 JWK thumbprint for an Ed25519 public key.
func Thumbprint(pub ed25519.PublicKey) (string, error) {
	k, err := jwk.FromRaw(pub)
	if err != nil {
		return "", err
	}
	thumb, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

func (k *KeyStore) KID() string                  { return k.kid }
func (k *KeyStore) Private() ed25519.PrivateKey  { return k.private }
func (k *KeyStore) PublicKey() ed25519.PublicKey { return k.public }
func (k *KeyStore) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(k.public)
}

// JWKS returns the JSON JWKS document with the active public key.
func (k *KeyStore) JWKS() ([]byte, error) {
	doc := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": k.kid,
				"x":   k.PublicKeyBase64(),
				"use": "sig",
			},
		},
	}
	return json.Marshal(doc)
}
