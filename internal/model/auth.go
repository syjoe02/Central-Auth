package model

type LoginRequest struct {
	UserID string `json:"user_id" binding:"required"`
	DeviceID string `json:"device_id" binding:"required"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}