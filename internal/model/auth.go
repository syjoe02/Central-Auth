package model

// LoginRequest is the body for POST /auth/login.
// Accepts either email+password credentials (delegated to Kratos for verification)
// or a pre-authenticated KratosID passed directly as user_id.
type LoginRequest struct {
	// Email+password path (used by Django integration)
	Email    string `json:"email"`
	Password string `json:"password"`
	// Pre-authenticated Kratos ID path (legacy / internal use)
	KratosID   string `json:"user_id"`
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

// SignupRequest is the body for POST /auth/signup.
type SignupRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// SignupResponse is the successful response from POST /auth/signup.
type SignupResponse struct {
	OryID string `json:"ory_id"`
	Email string `json:"email"`
}
