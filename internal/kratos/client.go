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

// ErrInvalidCredentials is returned by AuthenticatePassword when the email/password is wrong.
var ErrInvalidCredentials = errors.New("kratos: invalid credentials")

// Identity represents an Ory Kratos identity as returned by the Admin API.
type Identity struct {
	ID     string          `json:"id"`
	Traits json.RawMessage `json:"traits"`
}

// ClientI is the interface that the service layer depends on for Kratos operations.
type ClientI interface {
	GetIdentity(ctx context.Context, identityID string) (*Identity, error)
	// GetIdentityByEmail looks up an identity by email credential using the Admin API.
	// Returns ErrInvalidCredentials if no identity with that email exists.
	GetIdentityByEmail(ctx context.Context, email string) (*Identity, error)
	DeleteSessions(ctx context.Context, identityID string) error
	CreateIdentity(ctx context.Context, email, password string) (id string, err error)
	// AuthenticatePassword verifies email+password via Kratos self-service API mode
	// and returns the Kratos identity UUID on success.
	AuthenticatePassword(ctx context.Context, email, password string) (id string, err error)
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

// CreateIdentity creates a new Kratos identity with email + password credentials.
// Returns the new identity UUID on success, or an error if the email is already
// registered (HTTP 409) or the Admin API is unavailable.
func (c *Client) CreateIdentity(ctx context.Context, email, password string) (string, error) {
	type passwordConfig struct {
		Password string `json:"password"`
	}
	type credentials struct {
		Password struct {
			Config passwordConfig `json:"config"`
		} `json:"password"`
	}
	type traits struct {
		Email string `json:"email"`
	}
	body := struct {
		SchemaID    string      `json:"schema_id"`
		Traits      traits      `json:"traits"`
		Credentials credentials `json:"credentials"`
	}{
		SchemaID: "person",
		Traits:   traits{Email: email},
	}
	body.Credentials.Password.Config.Password = password

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

// AuthenticatePassword authenticates a user via the Kratos self-service API login
// flow (API mode — no browser required). Returns the Kratos identity UUID on success.
// Returns ErrInvalidCredentials for wrong email/password.
func (c *Client) AuthenticatePassword(ctx context.Context, email, password string) (string, error) {
	// Step 1: Initialise an API-mode login flow.
	initURL := fmt.Sprintf("%s/self-service/login/api", c.publicURL)
	initReq, err := http.NewRequestWithContext(ctx, http.MethodGet, initURL, nil)
	if err != nil {
		return "", fmt.Errorf("kratos: build init-login request: %w", err)
	}
	initResp, err := c.httpClient.Do(initReq)
	if err != nil {
		return "", fmt.Errorf("kratos: init login flow: %w", err)
	}
	defer initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kratos: unexpected status %d from init-login", initResp.StatusCode)
	}

	var initBody struct {
		ID  string `json:"id"`
		UI  struct {
			Action string `json:"action"`
		} `json:"ui"`
	}
	if err := json.NewDecoder(initResp.Body).Decode(&initBody); err != nil {
		return "", fmt.Errorf("kratos: decode init-login response: %w", err)
	}
	flowID := initBody.ID

	// Step 2: Submit password credentials.
	creds := map[string]any{
		"method":     "password",
		"identifier": email,
		"password":   password,
	}
	credsPayload, _ := json.Marshal(creds)
	submitURL := fmt.Sprintf("%s/self-service/login?flow=%s", c.publicURL, flowID)
	submitReq, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL, bytes.NewReader(credsPayload))
	if err != nil {
		return "", fmt.Errorf("kratos: build submit-login request: %w", err)
	}
	submitReq.Header.Set("Content-Type", "application/json")
	submitReq.Header.Set("Accept", "application/json")

	submitResp, err := c.httpClient.Do(submitReq)
	if err != nil {
		return "", fmt.Errorf("kratos: submit login: %w", err)
	}
	defer submitResp.Body.Close()

	if submitResp.StatusCode == http.StatusBadRequest || submitResp.StatusCode == http.StatusUnauthorized || submitResp.StatusCode == http.StatusForbidden {
		return "", ErrInvalidCredentials
	}
	if submitResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kratos: unexpected status %d from submit-login", submitResp.StatusCode)
	}

	var sessBody struct {
		Session struct {
			Identity struct {
				ID string `json:"id"`
			} `json:"identity"`
		} `json:"session"`
	}
	if err := json.NewDecoder(submitResp.Body).Decode(&sessBody); err != nil {
		return "", fmt.Errorf("kratos: decode submit-login response: %w", err)
	}
	id := sessBody.Session.Identity.ID
	if id == "" {
		return "", fmt.Errorf("kratos: missing identity id in login response")
	}
	return id, nil
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

// compile-time interface check
var _ ClientI = (*Client)(nil)
