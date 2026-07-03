package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

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

	oauthJWKS, err := jwk.Fetch(context.Background(), cfg.OAuthJWKSURL)
	if err != nil {
		slog.Error("oauth jwks fetch", "err", err)
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
