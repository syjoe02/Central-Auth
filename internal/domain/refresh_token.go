package domain

import "time"

type RefreshToken struct {
	UserID     string
	DeviceID   string
	TokenHash  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time // nullable
	UserAgent  *string
	IP         *string
	Revoked    bool
}
