package model

// LoginRequest is the body for POST /auth/login.
// KratosID is the Ory Kratos identity.id of the already-authenticated user.
// The json tag "user_id" is kept for backward compatibility with Django's integration.
type LoginRequest struct {
	KratosID   string `json:"user_id"  binding:"required"`
	DeviceID   string `json:"device_id" binding:"required"`
	RememberMe bool   `json:"remember_me"`
}

// LoginResponse is the successful response from POST /auth/login and POST /auth/refresh.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// BFFLoginRequest is the body for POST /bff/login.
// The json tag "user_id" is kept consistent with LoginRequest for Django compatibility.
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
