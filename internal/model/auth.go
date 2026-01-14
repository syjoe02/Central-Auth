package model

type LoginRequest struct {
	UserID string `json:"user_id" binding:"required"`
	DeviceID string `json:"device_id" binding:"required"`
	RememberMe bool `json:"remember_me"`
}

type OAuthLoginRequest struct {
	Provider   string `json:"provider" binding:"required"`
	IdToken    string `json:"id_token" binding:"required"`
	DeviceID   string `json:"device_id" binding:"required"`
	RememberMe bool   `json:"remember_me"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}