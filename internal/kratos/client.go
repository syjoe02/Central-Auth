// Package kratos provides a client for the Ory Kratos Admin and Public APIs.
// The central-auth service is an internal API gateway — it does not perform
// browser-based self-service flows. Kratos is used for identity look-ups and
// administrative session management only.
package kratos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Identity represents an Ory Kratos identity as returned by the Admin API.
type Identity struct {
	ID     string          `json:"id"`
	Traits json.RawMessage `json:"traits"`
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
