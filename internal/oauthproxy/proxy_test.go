package oauthproxy_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/3soos3/fit-issuer/internal/oauthproxy"
)

// ── test helpers ──────────────────────────────────────────────────────────────

const (
	testClientID     = "claude-desktop"
	testClientSecret = "mcp-secret"
	testProxyClientID = "proxy-client"
	testProxySecret   = "proxy-secret"
	testFITJWT        = "eyJhbGciOiJFZERTQSIsInR5cCI6IkZJVCtKV1QifQ.test.sig"
)

func pkce(verifier string) (challenge string) {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newProxy creates a Proxy pointed at dexTokenURL, with loginFn wired in.
// Returns both the Proxy and a ServeMux with routes registered.
func newProxy(dexTokenURL string, loginFn oauthproxy.LoginFunc) (*oauthproxy.Proxy, *http.ServeMux) {
	cfg := oauthproxy.Config{
		ServerURL:            "http://fit.example.org",
		DexAuthURL:           "http://dex.example.org/auth",
		DexTokenURL:          dexTokenURL,
		DexProxyClientID:     testProxyClientID,
		DexProxyClientSecret: testProxySecret,
		MCPClientID:          testClientID,
		MCPClientSecret:      testClientSecret,
	}
	p := oauthproxy.New(cfg, loginFn)
	mux := http.NewServeMux()
	p.RegisterRoutes(mux)
	return p, mux
}

func okLoginFn(_, _ string) (string, error) { return testFITJWT, nil }

// ── meta ──────────────────────────────────────────────────────────────────────

func TestOAuthMeta(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"issuer", "authorization_endpoint", "token_endpoint",
		"code_challenge_methods_supported", "resource_indicators_supported"} {
		if meta[key] == nil {
			t.Errorf("missing key %q in meta response", key)
		}
	}
	if meta["resource_indicators_supported"] != true {
		t.Errorf("resource_indicators_supported: got %v, want true", meta["resource_indicators_supported"])
	}
	if meta["issuer"] != "http://fit.example.org" {
		t.Errorf("issuer: got %v", meta["issuer"])
	}
}

// ── authorize ─────────────────────────────────────────────────────────────────

func TestOAuthAuthorize_RedirectsToDex(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	verifier := "test-verifier-string-that-is-43-chars-long!!"
	challenge := pkce(verifier)

	q := url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {"http://localhost:9999/cb"},
		"state":                 {"client-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil))

	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://dex.example.org/auth?") {
		t.Errorf("redirect should go to Dex, got: %s", loc)
	}
	parsed, _ := url.Parse(loc)
	if parsed.Query().Get("client_id") != testProxyClientID {
		t.Errorf("dex client_id: got %s", parsed.Query().Get("client_id"))
	}
	if parsed.Query().Get("state") == "" {
		t.Error("internal state missing from Dex redirect")
	}
}

func TestOAuthAuthorize_WrongClientID(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	q := url.Values{
		"client_id":             {"unknown-client"},
		"code_challenge":        {pkce("verifier")},
		"code_challenge_method": {"S256"},
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestOAuthAuthorize_MissingPKCE(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	tests := []struct {
		name      string
		challenge string
		method    string
	}{
		{"no challenge", "", "S256"},
		{"wrong method", pkce("v"), "plain"},
		{"no method", pkce("v"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{
				"client_id":             {testClientID},
				"code_challenge":        {tc.challenge},
				"code_challenge_method": {tc.method},
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil))
			if w.Code != http.StatusBadRequest {
				t.Errorf("want 400, got %d", w.Code)
			}
		})
	}
}

// ── token ─────────────────────────────────────────────────────────────────────

func TestOAuthToken_BadGrantType(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	body := strings.NewReader("grant_type=implicit&client_id=" + testClientID + "&client_secret=" + testClientSecret)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestOAuthToken_BadClient(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"code_verifier": {"some-verifier"},
		"client_id":     {"wrong"},
		"client_secret": {"wrong"},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestOAuthToken_InvalidCode(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"no-such-code"},
		"code_verifier": {"verifier"},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ── callback ──────────────────────────────────────────────────────────────────

func TestOAuthCallback_InvalidState(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/oauth/callback?code=abc&state=nonexistent", nil))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestOAuthCallback_MissingParams(t *testing.T) {
	_, mux := newProxy("", okLoginFn)

	for _, path := range []string{
		"/oauth/callback",
		"/oauth/callback?code=abc",
		"/oauth/callback?state=xyz",
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", path, w.Code)
		}
	}
}

func TestOAuthCallback_DexFails(t *testing.T) {
	// Dex returns 500
	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer dex.Close()

	_, mux := newProxy(dex.URL, okLoginFn)

	// Seed an auth state directly via the authorize endpoint
	verifier := "test-verifier-string-that-is-43-chars-long!!"
	challenge := pkce(verifier)
	q := url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {"http://localhost:9999/cb"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authW := httptest.NewRecorder()
	mux.ServeHTTP(authW, httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil))
	loc, _ := url.Parse(authW.Header().Get("Location"))
	internalState := loc.Query().Get("state")

	// Now call callback — Dex exchange will fail
	cbW := httptest.NewRecorder()
	mux.ServeHTTP(cbW, httptest.NewRequest("GET",
		fmt.Sprintf("/oauth/callback?code=dex-code&state=%s", url.QueryEscape(internalState)), nil))

	if cbW.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", cbW.Code)
	}
}

func TestOAuthCallback_LoginFnFails(t *testing.T) {
	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "dex-token"})
	}))
	defer dex.Close()

	failLogin := func(_, _ string) (string, error) { return "", errors.New("profile not found") }
	_, mux := newProxy(dex.URL, failLogin)

	// seed state
	verifier := "test-verifier-string-that-is-43-chars-long!!"
	q := url.Values{
		"client_id": {testClientID}, "redirect_uri": {"http://cb"},
		"state": {"s"}, "code_challenge": {pkce(verifier)},
		"code_challenge_method": {"S256"},
	}
	authW := httptest.NewRecorder()
	mux.ServeHTTP(authW, httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil))
	loc, _ := url.Parse(authW.Header().Get("Location"))
	internalState := loc.Query().Get("state")

	cbW := httptest.NewRecorder()
	mux.ServeHTTP(cbW, httptest.NewRequest("GET",
		"/oauth/callback?code=c&state="+url.QueryEscape(internalState), nil))

	if cbW.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", cbW.Code)
	}
}

// ── full flow ─────────────────────────────────────────────────────────────────

// TestOAuthFullFlow exercises the complete authorize → callback → token path.
func TestOAuthFullFlow(t *testing.T) {
	// Mock Dex token endpoint — returns a fixed id_token
	const dexIDToken = "dex.id.token"
	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		if r.FormValue("code") != "dex-auth-code" {
			http.Error(w, "wrong code", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": dexIDToken})
	}))
	defer dex.Close()

	// Login func asserts it received the right token and returns a known FIT
	loginFn := func(tok, _ string) (string, error) {
		if tok != dexIDToken {
			return "", fmt.Errorf("unexpected token: %q", tok)
		}
		return testFITJWT, nil
	}

	// Create a real test server so outbound HTTP from the proxy works
	mux := http.NewServeMux()
	fitSrv := httptest.NewUnstartedServer(mux)
	fitSrv.Start()
	defer fitSrv.Close()

	proxy := oauthproxy.New(oauthproxy.Config{
		ServerURL:            fitSrv.URL,
		DexAuthURL:           "http://dex.example.org/auth",
		DexTokenURL:          dex.URL,
		DexProxyClientID:     testProxyClientID,
		DexProxyClientSecret: testProxySecret,
		MCPClientID:          testClientID,
		MCPClientSecret:      testClientSecret,
	}, loginFn)
	proxy.RegisterRoutes(mux)

	// Non-redirecting HTTP client
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	verifier  := "test-code-verifier-that-is-43-chars-long!!!"
	challenge := pkce(verifier)

	// ── Step 1: authorize ────────────────────────────────────────────────────
	authResp, err := client.Get(fitSrv.URL + "/oauth/authorize?" + url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {"http://localhost:9999/cb"},
		"state":                 {"original-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: want 302, got %d", authResp.StatusCode)
	}
	dexLoc, _ := url.Parse(authResp.Header.Get("Location"))
	internalState := dexLoc.Query().Get("state")
	if internalState == "" {
		t.Fatal("no internal state in Dex redirect")
	}

	// ── Step 2: callback ─────────────────────────────────────────────────────
	cbResp, err := client.Get(fitSrv.URL + "/oauth/callback?" + url.Values{
		"code":  {"dex-auth-code"},
		"state": {internalState},
	}.Encode())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("callback: want 302, got %d", cbResp.StatusCode)
	}
	clientLoc, _ := url.Parse(cbResp.Header.Get("Location"))
	code := clientLoc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in client redirect")
	}
	if clientLoc.Query().Get("state") != "original-state" {
		t.Errorf("state echo: got %q", clientLoc.Query().Get("state"))
	}

	// ── Step 3: token exchange ────────────────────────────────────────────────
	tokResp, err := client.PostForm(fitSrv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token: want 200, got %d: %s", tokResp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(tokResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if result["access_token"] != testFITJWT {
		t.Errorf("access_token: got %v, want %s", result["access_token"], testFITJWT)
	}
	if result["token_type"] != "Bearer" {
		t.Errorf("token_type: got %v", result["token_type"])
	}

	// ── Step 3b: code is consumed — second use must fail ─────────────────────
	reuse, err := client.PostForm(fitSrv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	})
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	reuse.Body.Close()
	if reuse.StatusCode != http.StatusBadRequest {
		t.Errorf("code reuse: want 400, got %d", reuse.StatusCode)
	}
}

// TestOAuthFullFlow_ResourceThreaded verifies that the resource parameter is
// preserved through authorize → state → callback → loginFn.
func TestOAuthFullFlow_ResourceThreaded(t *testing.T) {
	const (
		dexIDToken       = "dex.id.token"
		wantResource     = "https://solve-it.example.org"
	)

	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": dexIDToken})
	}))
	defer dex.Close()

	var gotResource string
	loginFn := func(tok, resource string) (string, error) {
		gotResource = resource
		return testFITJWT, nil
	}

	mux := http.NewServeMux()
	fitSrv := httptest.NewUnstartedServer(mux)
	fitSrv.Start()
	defer fitSrv.Close()

	proxy := oauthproxy.New(oauthproxy.Config{
		ServerURL: fitSrv.URL, DexAuthURL: "http://dex.example.org/auth",
		DexTokenURL: dex.URL, DexProxyClientID: testProxyClientID,
		DexProxyClientSecret: testProxySecret,
		MCPClientID: testClientID, MCPClientSecret: testClientSecret,
	}, loginFn)
	proxy.RegisterRoutes(mux)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	verifier  := "test-code-verifier-that-is-43-chars-long!!!"
	challenge := pkce(verifier)

	// Step 1: authorize with resource parameter
	authResp, err := client.Get(fitSrv.URL + "/oauth/authorize?" + url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {"http://localhost:9999/cb"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {wantResource},
	}.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	authResp.Body.Close()
	dexLoc, _ := url.Parse(authResp.Header.Get("Location"))
	internalState := dexLoc.Query().Get("state")

	// Step 2: callback
	cbResp, err := client.Get(fitSrv.URL + "/oauth/callback?" + url.Values{
		"code":  {"dex-auth-code"},
		"state": {internalState},
	}.Encode())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cbResp.Body.Close()
	clientLoc, _ := url.Parse(cbResp.Header.Get("Location"))
	code := clientLoc.Query().Get("code")

	// Step 3: token exchange
	tokResp, err := client.PostForm(fitSrv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	tokResp.Body.Close()

	if gotResource != wantResource {
		t.Errorf("resource threaded to loginFn: got %q, want %q", gotResource, wantResource)
	}
}

// TestOAuthToken_PKCEMismatch confirms that a wrong code_verifier is rejected.
func TestOAuthToken_PKCEMismatch(t *testing.T) {
	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "tok"})
	}))
	defer dex.Close()

	mux := http.NewServeMux()
	fitSrv := httptest.NewUnstartedServer(mux)
	fitSrv.Start()
	defer fitSrv.Close()

	proxy := oauthproxy.New(oauthproxy.Config{
		ServerURL: fitSrv.URL, DexTokenURL: dex.URL,
		MCPClientID: testClientID, MCPClientSecret: testClientSecret,
		DexProxyClientID: testProxyClientID, DexProxyClientSecret: testProxySecret,
		DexAuthURL: "http://dex.example.org/auth",
	}, okLoginFn)
	proxy.RegisterRoutes(mux)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	verifier  := "correct-verifier-string-is-43-chars-long!!!"
	challenge := pkce(verifier)

	authResp, _ := client.Get(fitSrv.URL + "/oauth/authorize?" + url.Values{
		"client_id": {testClientID}, "redirect_uri": {"http://cb"},
		"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode())
	authResp.Body.Close()
	dexLoc, _ := url.Parse(authResp.Header.Get("Location"))

	cbResp, _ := client.Get(fitSrv.URL + "/oauth/callback?" + url.Values{
		"code": {"dex-code"}, "state": {dexLoc.Query().Get("state")},
	}.Encode())
	cbResp.Body.Close()
	clientLoc, _ := url.Parse(cbResp.Header.Get("Location"))
	code := clientLoc.Query().Get("code")

	// Use the wrong verifier
	tokResp, _ := client.PostForm(fitSrv.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"wrong-verifier"},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	})
	tokResp.Body.Close()

	if tokResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PKCE mismatch: want 400, got %d", tokResp.StatusCode)
	}
}

// TestOAuthToken_BasicAuth confirms the token endpoint accepts HTTP Basic auth.
func TestOAuthToken_BasicAuth(t *testing.T) {
	dex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "tok"})
	}))
	defer dex.Close()

	mux := http.NewServeMux()
	fitSrv := httptest.NewUnstartedServer(mux)
	fitSrv.Start()
	defer fitSrv.Close()

	proxy := oauthproxy.New(oauthproxy.Config{
		ServerURL: fitSrv.URL, DexTokenURL: dex.URL,
		MCPClientID: testClientID, MCPClientSecret: testClientSecret,
		DexProxyClientID: testProxyClientID, DexProxyClientSecret: testProxySecret,
		DexAuthURL: "http://dex.example.org/auth",
	}, okLoginFn)
	proxy.RegisterRoutes(mux)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	verifier  := "correct-verifier-string-is-43-chars-long!!!"
	challenge := pkce(verifier)

	authResp, _ := client.Get(fitSrv.URL + "/oauth/authorize?" + url.Values{
		"client_id": {testClientID}, "redirect_uri": {"http://cb"},
		"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode())
	authResp.Body.Close()
	dexLoc, _ := url.Parse(authResp.Header.Get("Location"))

	cbResp, _ := client.Get(fitSrv.URL + "/oauth/callback?" + url.Values{
		"code": {"dex-code"}, "state": {dexLoc.Query().Get("state")},
	}.Encode())
	cbResp.Body.Close()
	clientLoc, _ := url.Parse(cbResp.Header.Get("Location"))
	code := clientLoc.Query().Get("code")

	// POST with Basic auth (no client_id/secret in body)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
	}
	req, _ := http.NewRequest("POST", fitSrv.URL+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testClientSecret)

	tokResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("want 200, got %d: %s", tokResp.StatusCode, body)
	}
}
