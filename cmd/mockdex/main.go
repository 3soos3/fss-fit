// mockdex is a minimal OAuth server for local testing of fit-issuer.
// It serves a JWKS at /keys and issues signed JWTs at /token?sub=<sub>.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func main() {
	addr := "127.0.0.1:9998"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	issuer := "http://" + addr

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
	kid := thumbprint(pub)
	x := base64.RawURLEncoding.EncodeToString(pub)

	jwksBytes, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "OKP", "crv": "Ed25519",
			"kid": kid, "x": x, "use": "sig", "alg": "EdDSA",
		}},
	})

	mux := http.NewServeMux()

	// GET /keys — JWKS document
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	})

	// GET /token?sub=<sub>&exp=<seconds> — signed JWT for fit/login testing
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		if sub == "" {
			sub = "testuser@example.org"
		}
		expSecs := 3600
		tok := jwt.New()
		_ = tok.Set(jwt.SubjectKey, sub)
		_ = tok.Set(jwt.IssuerKey, issuer)
		_ = tok.Set(jwt.IssuedAtKey, time.Now())
		_ = tok.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(expSecs)*time.Second))

		hdrs := jws.NewHeaders()
		_ = hdrs.Set(jws.KeyIDKey, kid)
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, priv, jws.WithProtectedHeaders(hdrs)))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": string(signed)})
	})

	fmt.Printf("mockdex issuer:   %s\n", issuer)
	fmt.Printf("mockdex JWKS URL: %s/keys\n", issuer)
	fmt.Printf("mockdex token:    curl '%s/token?sub=analyst@example.org'\n", issuer)

	srv := &http.Server{Addr: addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "mockdex: %v\n", err)
		os.Exit(1)
	}
}

// thumbprint computes the RFC 7638 JWK thumbprint for an Ed25519 public key.
func thumbprint(pub ed25519.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub)
	input := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, x)
	h := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

