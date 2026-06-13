// Package kratos provides a client for the Ory Kratos Admin and Public APIs.
// The central-auth service is an internal API gateway — it does not perform
// browser-based self-service flows. Kratos is used for identity look-ups and
// administrative session management only.
package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrEmailConflict is returned by CreateIdentity when the email is already registered.
var ErrEmailConflict = errors.New("kratos: email already registered")

// ErrInvalidCredentials is returned by GetIdentityByEmail when no identity with that email exists.
var ErrInvalidCredentials = errors.New("kratos: invalid credentials")

// Identity represents an Ory Kratos identity as returned by the Admin API.
type Identity struct {
	ID     string          `json:"id"`
	Traits json.RawMessage `json:"traits"`
}

// IdentityFull extends Identity with the credentials map returned by the Admin API.
// Credentials keys ("oidc", "password", etc.) indicate which login providers are
// configured for this identity. Values are raw JSON — only key existence is checked.
type IdentityFull struct {
	ID          string                     `json:"id"`
	Traits      json.RawMessage            `json:"traits"`
	Credentials map[string]json.RawMessage `json:"credentials"`
}

// ClientI is the interface that the service layer depends on for Kratos operations.
type ClientI interface {
	GetIdentity(ctx context.Context, identityID string) (*Identity, error)
	// GetIdentityByEmail looks up an identity by email credential using the Admin API.
	// Returns ErrInvalidCredentials if no identity with that email exists.
	GetIdentityByEmail(ctx context.Context, email string) (*Identity, error)
	DeleteSessions(ctx context.Context, identityID string) error
	CreateIdentity(ctx context.Context, email string) (id string, err error)
	// GetSessionIDByToken resolves the Kratos session UUID for a given session token.
	// Called at BFF login time to capture the session ID for targeted revocation on logout.
	GetSessionIDByToken(ctx context.Context, sessionToken string) (string, error)
	// DeleteSession deletes a single Kratos session by its UUID via the Admin API.
	// Returns nil if the session is already gone (idempotent).
	DeleteSession(ctx context.Context, kratosSessionID string) error
	// GetIdentityFull fetches identity metadata including the credentials map,
	// used to determine the user's login provider (Google OIDC vs. password).
	GetIdentityFull(ctx context.Context, identityID string) (*IdentityFull, error)
}

// Client wraps the Ory Kratos Admin and Public HTTP APIs.
type Client struct {
	adminURL   string
	publicURL  string
	httpClient *http.Client
}

// New creates a new Kratos Client.
func New(adminURL, publicURL string) *Client {
	return &Client{
		adminURL:  adminURL,
		publicURL: publicURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetIdentity fetches an identity by its Kratos UUID from the Admin API.
// Returns an error if the identity does not exist or if the Admin API is unavailable.
func (c *Client) GetIdentity(ctx context.Context, identityID string) (*Identity, error) {
	url := fmt.Sprintf("%s/admin/identities/%s", c.adminURL, identityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kratos: build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kratos: admin request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("kratos: identity %s not found", identityID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kratos: unexpected status %d from admin/identities", resp.StatusCode)
	}

	var identity Identity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, fmt.Errorf("kratos: decode identity response: %w", err)
	}
	return &identity, nil
}

// GetIdentityFull fetches a Kratos identity including the credentials map.
// Use this when you need to determine the user's login provider (oidc vs password).
func (c *Client) GetIdentityFull(ctx context.Context, identityID string) (*IdentityFull, error) {
	url := fmt.Sprintf("%s/admin/identities/%s", c.adminURL, identityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kratos: build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kratos: admin request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("kratos: identity %s not found", identityID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kratos: unexpected status %d from admin/identities", resp.StatusCode)
	}

	var identity IdentityFull
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, fmt.Errorf("kratos: decode identity-full response: %w", err)
	}
	return &identity, nil
}

// CreateIdentity creates a new Kratos identity with email trait only (no password credential).
// The identity is linked to Google OIDC automatically on the user's first Google login.
// Returns the new identity UUID on success, or an error if the email is already
// registered (HTTP 409) or the Admin API is unavailable.
func (c *Client) CreateIdentity(ctx context.Context, email string) (string, error) {
	body := struct {
		SchemaID string `json:"schema_id"`
		Traits   struct {
			Email string `json:"email"`
		} `json:"traits"`
	}{
		SchemaID: "person",
	}
	body.Traits.Email = email

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("kratos: marshal create identity body: %w", err)
	}

	url := fmt.Sprintf("%s/admin/identities", c.adminURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("kratos: build create-identity request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kratos: create identity request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return "", ErrEmailConflict
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("kratos: unexpected status %d from create identity", resp.StatusCode)
	}

	var identity Identity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return "", fmt.Errorf("kratos: decode create identity response: %w", err)
	}
	return identity.ID, nil
}

// DeleteSessions deletes all Kratos sessions for a given identity.
// Used during LogoutAll to invalidate any browser-based Kratos sessions alongside
// the Hydra OAuth2 token revocation.
func (c *Client) DeleteSessions(ctx context.Context, identityID string) error {
	url := fmt.Sprintf("%s/admin/identities/%s/sessions", c.adminURL, identityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("kratos: build delete-sessions request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kratos: delete sessions request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kratos: unexpected status %d from delete sessions", resp.StatusCode)
	}
	return nil
}

// GetIdentityByEmail looks up a Kratos identity using the credentials_identifier
// query parameter on the Admin list-identities endpoint. Returns ErrInvalidCredentials
// when no identity with that email exists.
func (c *Client) GetIdentityByEmail(ctx context.Context, email string) (*Identity, error) {
	url := fmt.Sprintf("%s/admin/identities?credentials_identifier=%s", c.adminURL, email)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kratos: build get-by-email request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kratos: get-by-email request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kratos: unexpected status %d from list identities", resp.StatusCode)
	}

	var identities []Identity
	if err := json.NewDecoder(resp.Body).Decode(&identities); err != nil {
		return nil, fmt.Errorf("kratos: decode list-identities response: %w", err)
	}
	if len(identities) == 0 {
		return nil, ErrInvalidCredentials
	}
	return &identities[0], nil
}

// GetSessionIDByToken resolves the Kratos session UUID for the given opaque session token.
// Called at BFF login time; the token is the value of the ory_kratos_session cookie.
func (c *Client) GetSessionIDByToken(ctx context.Context, sessionToken string) (string, error) {
	url := c.publicURL + "/sessions/whoami"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("kratos: build whoami request: %w", err)
	}
	req.Header.Set("X-Session-Token", sessionToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kratos: whoami request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("kratos: session token invalid or expired")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kratos: unexpected status %d from whoami", resp.StatusCode)
	}

	var sess struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		return "", fmt.Errorf("kratos: decode whoami response: %w", err)
	}
	if sess.ID == "" {
		return "", fmt.Errorf("kratos: whoami returned empty session ID")
	}
	return sess.ID, nil
}

// DeleteSession deletes a specific Kratos session by its UUID via the Admin API.
// Returns nil if the session does not exist (idempotent).
func (c *Client) DeleteSession(ctx context.Context, kratosSessionID string) error {
	url := fmt.Sprintf("%s/admin/sessions/%s", c.adminURL, kratosSessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("kratos: build delete-session request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kratos: delete session request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // already gone, idempotent
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kratos: unexpected status %d from delete session", resp.StatusCode)
	}
	return nil
}

// compile-time interface check
var _ ClientI = (*Client)(nil)
