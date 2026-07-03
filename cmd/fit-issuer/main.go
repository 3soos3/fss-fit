package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/3soos3/fit-issuer/internal/config"
	"github.com/3soos3/fit-issuer/internal/handlers"
	"github.com/3soos3/fit-issuer/internal/keys"
	"github.com/3soos3/fit-issuer/internal/profiles"
	"github.com/3soos3/fit-issuer/internal/revocation"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	ks, err := keys.LoadOrGenerate(cfg.DataDir)
	if err != nil {
		slog.Error("keys", "err", err)
		os.Exit(1)
	}

	store, err := revocation.New(cfg.DataDir)
	if err != nil {
		slog.Error("revocation", "err", err)
		os.Exit(1)
	}

	reg, err := profiles.Load(cfg.ProfilesConfig)
	if err != nil {
		slog.Error("profiles", "err", err)
		os.Exit(1)
	}

	oauthJWKS, err := fetchWithRetry(cfg.OAuthJWKSURL, 3, 5*time.Second)
	if err != nil {
		slog.Error("oauth jwks fetch failed after retries", "url", cfg.OAuthJWKSURL, "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/fss-jwks.json", handlers.JWKS(ks))
	mux.HandleFunc("GET /health", handlers.Health(ks, store))
	mux.HandleFunc("POST /fit/login", handlers.Login(cfg, ks, reg, oauthJWKS))
	mux.HandleFunc("POST /fit/issue", handlers.Issue(cfg, ks, reg))
	mux.HandleFunc("POST /fit/revoke", handlers.Revoke(cfg, store))
	mux.HandleFunc("POST /fit/verify", handlers.Verify(cfg, ks, store))

	slog.Info("fit-issuer starting", "addr", ":8090")
	if err := http.ListenAndServe(":8090", mux); err != nil {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}

// fetchWithRetry attempts to fetch a JWKS up to maxAttempts times,
// waiting delay between each attempt. Transient unavailability (e.g.
// OAuth provider still starting) is handled; persistent failure exits.
func fetchWithRetry(url string, maxAttempts int, delay time.Duration) (jwk.Set, error) {
	var (
		set jwk.Set
		err error
	)
	for i := 1; i <= maxAttempts; i++ {
		set, err = jwk.Fetch(context.Background(), url)
		if err == nil {
			return set, nil
		}
		if i < maxAttempts {
			slog.Warn("oauth jwks fetch failed, retrying",
				"attempt", i,
				"max", maxAttempts,
				"url", url,
				"err", err,
			)
			time.Sleep(delay)
		}
	}
	return nil, err
}
