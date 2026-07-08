// Package oauthproxy turns fit-issuer into an OAuth 2.0 authorization server
// for Claude Desktop (and any MCP HTTP client that speaks RFC 6749 + PKCE).
//
// Flow:
//  1. Client → GET  /oauth/authorize   (PKCE S256, client_id=claude-desktop)
//  2. Proxy  → 302 → Dex /dex/auth    (proxy Dex client)
//  3. User logs in at Dex
//  4. Dex    → GET  /oauth/callback    (Dex auth code)
//  5. Proxy exchanges Dex code → Dex ID token → LoginFunc → FIT JWT
//  6. Proxy  → 302 → client redirect_uri with short-lived code
//  7. Client → POST /oauth/token       (code + code_verifier PKCE)
//  8. Proxy verifies PKCE → returns FIT JWT as access_token
package oauthproxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	authStateTTL = 5 * time.Minute
	codeTTL      = 2 * time.Minute
)

// LoginFunc converts a Dex ID token and the OAuth resource URL into a signed FIT JWT.
// The resource URL (RFC 8707) identifies which MCP server initiated the flow and
// is used to select the appropriate issuance profile.
// Returned by handlers.MakeLoginFunc and injected via New.
type LoginFunc func(dexIDToken, resource string) (string, error)

// Config holds OAuth proxy configuration, separate from the main fit-issuer config.
type Config struct {
	ServerURL            string // public base URL of this service, e.g. "https://iat.example.org"
	DexAuthURL           string // Dex authorization endpoint
	DexTokenURL          string // Dex token endpoint
	DexProxyClientID     string // Dex client ID registered for this proxy
	DexProxyClientSecret string
	MCPClientID          string // OAuth client_id for MCP clients (e.g. "claude-desktop")
	MCPClientSecret      string
}

// Proxy is an OAuth 2.0 authorization server that wraps FIT issuance.
type Proxy struct {
	cfg     Config
	loginFn LoginFunc
	store   *proxyStore
}

// New creates a Proxy and starts its background TTL-cleanup goroutine.
func New(cfg Config, loginFn LoginFunc) *Proxy {
	return &Proxy{
		cfg:     cfg,
		loginFn: loginFn,
		store:   newProxyStore(),
	}
}

// RegisterRoutes registers the four OAuth proxy endpoints on mux.
func (p *Proxy) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", p.handleMeta)
	mux.HandleFunc("GET /oauth/authorize", p.handleAuthorize)
	mux.HandleFunc("GET /oauth/callback", p.handleCallback)
	mux.HandleFunc("POST /oauth/token", p.handleToken)
}

// ── in-memory state store ─────────────────────────────────────────────────────

type authEntry struct {
	codeChallenge string
	redirectURI   string
	clientState   string
	resource      string // RFC 8707 resource indicator — MCP server URL
	created       time.Time
}

type codeEntry struct {
	fitJWT        string
	codeChallenge string
	redirectURI   string
	resource      string
	created       time.Time
}

type proxyStore struct {
	mu    sync.Mutex
	auth  map[string]*authEntry
	codes map[string]*codeEntry
}

func newProxyStore() *proxyStore {
	s := &proxyStore{
		auth:  make(map[string]*authEntry),
		codes: make(map[string]*codeEntry),
	}
	go s.cleanup()
	return s
}

func (s *proxyStore) cleanup() {
	for {
		time.Sleep(time.Minute)
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.auth {
			if now.Sub(v.created) > authStateTTL {
				delete(s.auth, k)
			}
		}
		for k, v := range s.codes {
			if now.Sub(v.created) > codeTTL {
				delete(s.codes, k)
			}
		}
		s.mu.Unlock()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ── handlers ──────────────────────────────────────────────────────────────────

func (p *Proxy) handleMeta(w http.ResponseWriter, _ *http.Request) {
	meta := map[string]any{
		"issuer":                                p.cfg.ServerURL,
		"authorization_endpoint":                p.cfg.ServerURL + "/oauth/authorize",
		"token_endpoint":                        p.cfg.ServerURL + "/oauth/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"resource_indicators_supported":         true, // RFC 8707 — MCP clients send resource= to select issuance profile
	}
	writeJSON(w, http.StatusOK, meta)
}

func (p *Proxy) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID    := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state       := q.Get("state")
	challenge   := q.Get("code_challenge")
	method      := q.Get("code_challenge_method")
	resource    := q.Get("resource") // RFC 8707 — MCP server URL

	if clientID != p.cfg.MCPClientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if challenge == "" || method != "S256" {
		http.Error(w, "PKCE with S256 is required", http.StatusBadRequest)
		return
	}

	internalState := randomHex(16)
	p.store.mu.Lock()
	p.store.auth[internalState] = &authEntry{
		codeChallenge: challenge,
		redirectURI:   redirectURI,
		clientState:   state,
		resource:      resource,
		created:       time.Now(),
	}
	p.store.mu.Unlock()

	dexURL := p.cfg.DexAuthURL + "?" + url.Values{
		"client_id":     {p.cfg.DexProxyClientID},
		"redirect_uri":  {p.cfg.ServerURL + "/oauth/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {internalState},
	}.Encode()

	http.Redirect(w, r, dexURL, http.StatusFound)
}

func (p *Proxy) handleCallback(w http.ResponseWriter, r *http.Request) {
	q             := r.URL.Query()
	dexCode       := q.Get("code")
	internalState := q.Get("state")

	if dexCode == "" || internalState == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	p.store.mu.Lock()
	as, ok := p.store.auth[internalState]
	if ok {
		delete(p.store.auth, internalState)
	}
	p.store.mu.Unlock()

	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	dexIDToken, err := exchangeDexCode(p.cfg, dexCode)
	if err != nil {
		slog.Error("dex code exchange failed", "err", err)
		http.Error(w, "upstream token exchange failed", http.StatusBadGateway)
		return
	}

	fitJWT, err := p.loginFn(dexIDToken, as.resource)
	if err != nil {
		slog.Error("fit login failed", "err", err)
		http.Error(w, "FIT issuance failed", http.StatusBadGateway)
		return
	}

	code := randomHex(16)
	p.store.mu.Lock()
	p.store.codes[code] = &codeEntry{
		fitJWT:        fitJWT,
		codeChallenge: as.codeChallenge,
		redirectURI:   as.redirectURI,
		resource:      as.resource,
		created:       time.Now(),
	}
	p.store.mu.Unlock()

	redir := as.redirectURI + "?code=" + url.QueryEscape(code)
	if as.clientState != "" {
		redir += "&state=" + url.QueryEscape(as.clientState)
	}
	http.Redirect(w, r, redir, http.StatusFound)
}

func (p *Proxy) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid form body"))
		return
	}

	clientID, clientSecret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID     = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	grantType := r.FormValue("grant_type")
	code      := r.FormValue("code")
	verifier  := r.FormValue("code_verifier")

	if grantType != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, errResp("unsupported grant_type"))
		return
	}
	if clientID != p.cfg.MCPClientID || clientSecret != p.cfg.MCPClientSecret {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid client credentials"))
		return
	}

	p.store.mu.Lock()
	cs, ok := p.store.codes[code]
	if ok {
		delete(p.store.codes, code)
	}
	p.store.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusBadRequest, errResp("invalid or expired code"))
		return
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if computed != cs.codeChallenge {
		writeJSON(w, http.StatusBadRequest, errResp("code_verifier mismatch"))
		return
	}

	slog.Info("FIT_ISSUED", "event", "FIT_ISSUED", "issued_by", "oauth-proxy", "resource", cs.resource)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": cs.fitJWT,
		"token_type":   "Bearer",
		"expires_in":   86400,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func exchangeDexCode(cfg Config, code string) (string, error) {
	resp, err := http.PostForm(cfg.DexTokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.ServerURL + "/oauth/callback"},
		"client_id":     {cfg.DexProxyClientID},
		"client_secret": {cfg.DexProxyClientSecret},
	})
	if err != nil {
		return "", fmt.Errorf("dex token POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dex token %s: %s", resp.Status, body)
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("dex token parse: %w", err)
	}
	if tok.IDToken != "" {
		return tok.IDToken, nil
	}
	return tok.AccessToken, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errResp(msg string) map[string]string {
	return map[string]string{"error": msg}
}
