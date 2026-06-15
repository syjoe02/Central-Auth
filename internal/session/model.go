// Package session provides the BFF session model and Redis-backed store.
// BFF sessions map an opaque browser cookie to a server-side record that
// holds Hydra tokens. Tokens never leave the server.
package session

import "time"

// BFFSession holds all server-side state for a single browser session.
// SessionID is an opaque 64-character hex string stored in the browser's
// HttpOnly cookie; Hydra access/refresh tokens are never exposed to the client.
type BFFSession struct {
	SessionID         string    `json:"session_id"`
	KratosID          string    `json:"kratos_id"`
	DeviceID          string    `json:"device_id"`
	// KratosSessionID is the Kratos session UUID captured at BFF login.
	// Used to delete the specific Kratos session on logout rather than all sessions.
	// Empty for sessions created before this field was introduced (fallback: delete all).
	KratosSessionID   string    `json:"kratos_session_id,omitempty"`
	HydraAccessToken  string    `json:"hydra_access_token"`
	HydraRefreshToken string    `json:"hydra_refresh_token"`
	// AccessTokenExp is parsed from the Hydra JWT exp claim and used to
	// schedule proactive token refresh (transparent to the browser).
	AccessTokenExp    time.Time `json:"access_token_exp"`
	CreatedAt         time.Time `json:"created_at"`
	// ExpiresAt is the session-level TTL, aligned with the Hydra refresh token TTL.
	ExpiresAt         time.Time `json:"expires_at"`
}
