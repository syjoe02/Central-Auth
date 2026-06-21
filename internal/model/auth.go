package model

// LoginResponse is the successful response from POST /auth/google/login and POST /auth/refresh.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// BFFLoginRequest is the body for POST /bff/login.
// The json tag "user_id" is the established API contract for this endpoint.
type BFFLoginRequest struct {
	KratosID   string `json:"user_id"   binding:"required"`
	DeviceID   string `json:"device_id" binding:"required"`
	RememberMe bool   `json:"remember_me"`
}

// BFFStatusResponse is returned by BFF state-changing operations.
type BFFStatusResponse struct {
	Status string `json:"status"`
}

// WhoAmIResponse is returned by GET /bff/whoami.
type WhoAmIResponse struct {
	KratosID string `json:"kratos_id"`
	DeviceID string `json:"device_id"`
}

// SignupRequest is the body for POST /auth/signup.
// Only email is required; no password credential is created on the Kratos identity.
// Google OIDC is linked automatically on the user's first Google login.
type SignupRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// SignupResponse is the successful response from POST /auth/signup.
type SignupResponse struct {
	OryID string `json:"ory_id"`
	Email string `json:"email"`
}
