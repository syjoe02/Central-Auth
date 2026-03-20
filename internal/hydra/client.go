// Package hydra provides a client for the Ory Hydra OAuth2 Admin and Public APIs.
//
// The central-auth service implements Hydra's programmatic login/consent flow
// entirely server-side. No browser redirects are issued — the Go service acts as
// both the OAuth2 client AND the login/consent provider, calling Hydra's Admin API
// to accept challenges without HTTP callbacks.
//
// Token validation uses Hydra's JWT access token strategy: access tokens are RS256
// JWTs whose public keys are fetched from Hydra's JWKS endpoint and cached locally.
// This keeps /auth/verify a zero-network-call operation for valid, non-expired tokens.
package hydra

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenSet is the token response returned by Hydra's token endpoint.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// IntrospectResult is the response from Hydra's token introspection endpoint.
type IntrospectResult struct {
	Active   bool                   `json:"active"`
	Subject  string                 `json:"sub"`
	Ext      map[string]interface{} `json:"ext"`
	ClientID string                 `json:"client_id"`
	Exp      int64                  `json:"exp"`
}

// DeviceID extracts the device_id from the ext claims.
func (r *IntrospectResult) DeviceID() string {
	if r.Ext == nil {
		return ""
	}
	if v, ok := r.Ext["device_id"].(string); ok {
		return v
	}
	return ""
}

// AccessTokenClaims holds the parsed claims from a Hydra-issued JWT access token.
type AccessTokenClaims struct {
	Subject  string                 `json:"sub"`
	Ext      map[string]interface{} `json:"ext"`
	ClientID string                 `json:"client_id"`
	jwt.RegisteredClaims
}

// DeviceID extracts device_id from the ext map.
func (c *AccessTokenClaims) DeviceID() string {
	if c.Ext == nil {
		return ""
	}
	if v, ok := c.Ext["device_id"].(string); ok {
		return v
	}
	return ""
}

// ClientI is the interface that the service layer depends on.
// *Client satisfies it; tests can provide a mock.
type ClientI interface {
	IssueTokens(ctx context.Context, kratosID, deviceID string, rememberMe bool) (*TokenSet, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error)
	RevokeToken(ctx context.Context, token string) error
	RevokeAllForSubject(ctx context.Context, kratosID string) error
	IntrospectToken(ctx context.Context, token string) (*IntrospectResult, error)
	ValidateAccessToken(ctx context.Context, tokenStr string) (*AccessTokenClaims, error)
}

// compile-time check
var _ ClientI = (*Client)(nil)

// jwkKey represents a single JSON Web Key entry.
type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksResponse is the response from the JWKS endpoint.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwksCache caches public keys fetched from Hydra's JWKS endpoint.
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
}

func newJWKSCache() *jwksCache {
	return &jwksCache{
		keys: make(map[string]*rsa.PublicKey),
		ttl:  1 * time.Hour,
	}
}

func (jc *jwksCache) get(kid string) (*rsa.PublicKey, bool) {
	jc.mu.RLock()
	defer jc.mu.RUnlock()
	k, ok := jc.keys[kid]
	return k, ok
}

func (jc *jwksCache) set(keys map[string]*rsa.PublicKey) {
	jc.mu.Lock()
	defer jc.mu.Unlock()
	jc.keys = keys
	jc.fetchedAt = time.Now()
}

func (jc *jwksCache) isStale() bool {
	jc.mu.RLock()
	defer jc.mu.RUnlock()
	return time.Since(jc.fetchedAt) > jc.ttl
}

// Client wraps the Ory Hydra Admin and Public HTTP APIs.
type Client struct {
	publicURL    string
	adminURL     string
	clientID     string
	clientSecret string
	redirectURI  string

	// httpClient follows redirects (used for token exchange).
	httpClient *http.Client
	// noRedirectClient does NOT follow redirects (used for the programmatic auth code flow).
	noRedirectClient *http.Client

	jwks *jwksCache
}

// New creates a new Hydra Client.
func New(publicURL, adminURL, clientID, clientSecret, redirectURI string) *Client {
	return &Client{
		publicURL:    publicURL,
		adminURL:     adminURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		noRedirectClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		jwks: newJWKSCache(),
	}
}

// IssueTokens runs the full programmatic authorization code flow server-side:
//  1. GET /oauth2/auth                       → extract login_challenge from redirect
//  2. PUT /admin/…/login/accept              → get redirect_to
//  3. GET redirect_to                        → extract consent_challenge from redirect
//  4. PUT /admin/…/consent/accept            → get redirect_to
//  5. GET redirect_to                        → extract authorization code from redirect
//  6. POST /oauth2/token (grant_type=code)   → return TokenSet
//
// device_id is embedded in the token ext claims so /auth/verify can identify the
// device locally from the JWT without an additional Hydra introspection call.
func (c *Client) IssueTokens(ctx context.Context, kratosID, deviceID string, rememberMe bool) (*TokenSet, error) {
	state, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("hydra: generate state: %w", err)
	}
	nonce, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("hydra: generate nonce: %w", err)
	}

	// ── Step 1: Initiate OAuth2 authorization flow ──────────────────────────
	authParams := url.Values{
		"response_type": {"code"},
		"client_id":     {c.clientID},
		"redirect_uri":  {c.redirectURI},
		"scope":         {"openid offline_access email profile"},
		"state":         {state},
		"nonce":         {nonce},
	}
	authURL := c.publicURL + "/oauth2/auth?" + authParams.Encode()

	resp1, err := c.noRedirectClient.Get(authURL)
	if err != nil {
		return nil, fmt.Errorf("hydra: initiate auth flow: %w", err)
	}
	resp1.Body.Close()

	loginChallenge, err := extractParam(resp1.Header.Get("Location"), "login_challenge")
	if err != nil {
		return nil, fmt.Errorf("hydra: extract login_challenge: %w", err)
	}

	// ── Step 2: Accept login challenge ──────────────────────────────────────
	rememberFor := 0
	if rememberMe {
		rememberFor = 60 * 60 * 24 * 30 // 30 days in seconds
	}
	loginAcceptBody := map[string]interface{}{
		"subject":      kratosID,
		"remember":     rememberMe,
		"remember_for": rememberFor,
		"context":      map[string]string{"device_id": deviceID},
	}
	redirectTo1, err := c.adminAccept(ctx, "/admin/oauth2/auth/requests/login/accept?login_challenge="+loginChallenge, loginAcceptBody)
	if err != nil {
		return nil, fmt.Errorf("hydra: accept login: %w", err)
	}

	// ── Step 3: Follow redirect_to to reach consent challenge ───────────────
	resp3, err := c.noRedirectClient.Get(redirectTo1)
	if err != nil {
		return nil, fmt.Errorf("hydra: follow login redirect: %w", err)
	}
	resp3.Body.Close()

	consentChallenge, err := extractParam(resp3.Header.Get("Location"), "consent_challenge")
	if err != nil {
		return nil, fmt.Errorf("hydra: extract consent_challenge: %w", err)
	}

	// ── Step 4: Accept consent (embed device_id in ext claims) ──────────────
	consentAcceptBody := map[string]interface{}{
		"grant_scope":                 []string{"openid", "offline_access", "email", "profile"},
		"grant_access_token_audience": []string{c.clientID},
		"remember":                    rememberMe,
		"remember_for":                rememberFor,
		"session": map[string]interface{}{
			"access_token": map[string]string{"device_id": deviceID},
			"id_token":     map[string]string{"device_id": deviceID},
		},
	}
	redirectTo2, err := c.adminAccept(ctx, "/admin/oauth2/auth/requests/consent/accept?consent_challenge="+consentChallenge, consentAcceptBody)
	if err != nil {
		return nil, fmt.Errorf("hydra: accept consent: %w", err)
	}

	// ── Step 5: Follow redirect_to to receive the authorization code ─────────
	resp5, err := c.noRedirectClient.Get(redirectTo2)
	if err != nil {
		return nil, fmt.Errorf("hydra: follow consent redirect: %w", err)
	}
	resp5.Body.Close()

	code, err := extractParam(resp5.Header.Get("Location"), "code")
	if err != nil {
		return nil, fmt.Errorf("hydra: extract authorization code: %w", err)
	}
	returnedState, _ := extractParam(resp5.Header.Get("Location"), "state")
	if returnedState != state {
		return nil, errors.New("hydra: state mismatch — possible CSRF")
	}

	// ── Step 6: Exchange code for tokens ────────────────────────────────────
	return c.exchangeCode(ctx, code)
}

// RefreshToken exchanges a Hydra refresh token for a new access+refresh token pair.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	return c.tokenRequest(ctx, data)
}

// RevokeToken revokes a Hydra access or refresh token via the public revocation endpoint.
func (c *Client) RevokeToken(ctx context.Context, token string) error {
	data := url.Values{
		"token":         {token},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.publicURL+"/oauth2/revoke",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return fmt.Errorf("hydra: build revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hydra: revoke request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hydra: unexpected revoke status %d", resp.StatusCode)
	}
	return nil
}

// RevokeAllForSubject deletes all OAuth2 tokens for a Kratos identity from Hydra.
func (c *Client) RevokeAllForSubject(ctx context.Context, kratosID string) error {
	params := url.Values{
		"subject":   {kratosID},
		"client_id": {c.clientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.adminURL+"/admin/oauth2/tokens?"+params.Encode(),
		nil,
	)
	if err != nil {
		return fmt.Errorf("hydra: build revoke-all request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hydra: revoke-all request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hydra: unexpected revoke-all status %d", resp.StatusCode)
	}
	return nil
}

// IntrospectToken calls Hydra's Admin introspection endpoint.
// Used to extract the subject and device_id from an opaque refresh token.
func (c *Client) IntrospectToken(ctx context.Context, token string) (*IntrospectResult, error) {
	data := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.adminURL+"/admin/oauth2/introspect",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("hydra: build introspect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hydra: introspect request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hydra: unexpected introspect status %d", resp.StatusCode)
	}

	var result IntrospectResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hydra: decode introspect response: %w", err)
	}
	return &result, nil
}

// ValidateAccessToken validates a Hydra-issued JWT access token locally using
// cached JWKS public keys. This is the fast path for /auth/verify.
// Fail-closed: any error returns a non-nil error.
func (c *Client) ValidateAccessToken(ctx context.Context, tokenStr string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("hydra: unexpected signing method %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		return c.resolveKey(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("hydra: token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("hydra: token is not valid")
	}
	return claims, nil
}

// ── private helpers ──────────────────────────────────────────────────────────

func (c *Client) adminAccept(ctx context.Context, path string, body interface{}) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.adminURL+path,
		bytes.NewReader(b),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("hydra admin PUT %s → %d: %s", path, resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("hydra: decode admin accept response: %w", err)
	}
	return result.RedirectTo, nil
}

func (c *Client) exchangeCode(ctx context.Context, code string) (*TokenSet, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.redirectURI},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	return c.tokenRequest(ctx, data)
}

func (c *Client) tokenRequest(ctx context.Context, data url.Values) (*TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.publicURL+"/oauth2/token",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("hydra: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hydra: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hydra: token endpoint → %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var ts TokenSet
	if err := json.NewDecoder(resp.Body).Decode(&ts); err != nil {
		return nil, fmt.Errorf("hydra: decode token response: %w", err)
	}
	return &ts, nil
}

func (c *Client) resolveKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if !c.jwks.isStale() {
		if k, ok := c.jwks.get(kid); ok {
			return k, nil
		}
	}
	if err := c.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	k, ok := c.jwks.get(kid)
	if !ok {
		return nil, fmt.Errorf("hydra: no JWKS key found for kid=%q", kid)
	}
	return k, nil
}

func (c *Client) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.publicURL+"/.well-known/jwks.json",
		nil,
	)
	if err != nil {
		return fmt.Errorf("hydra: build JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hydra: JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hydra: JWKS endpoint → %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("hydra: decode JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	c.jwks.set(keys)
	return nil
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func extractParam(rawURL, param string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty redirect URL when extracting %q", param)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse redirect URL: %w", err)
	}
	v := u.Query().Get(param)
	if v == "" {
		return "", fmt.Errorf("param %q not found in redirect URL: %s", param, rawURL)
	}
	return v, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
