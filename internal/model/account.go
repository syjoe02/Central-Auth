package model

import "time"

// AccountMeResponse is returned by GET /bff/account/me.
type AccountMeResponse struct {
	Email         string `json:"email"`
	Name          string `json:"name"`
	LoginProvider string `json:"loginProvider"` // "Google" or "Password"
}

// DeviceInfo represents one active device session.
type DeviceInfo struct {
	DeviceID   string     `json:"deviceId"`
	Browser    string     `json:"browser"`
	OS         string     `json:"os"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	IsCurrent  bool       `json:"isCurrent"`
}

// SessionsResponse is returned by GET /bff/account/sessions.
type SessionsResponse struct {
	CurrentDevice *DeviceInfo  `json:"currentDevice"`
	OtherDevices  []DeviceInfo `json:"otherDevices"`
}

// LogoutDevicesRequest is the body for POST /bff/logout-devices.
type LogoutDevicesRequest struct {
	DeviceIDs []string `json:"deviceIds" binding:"required,min=1"`
}
