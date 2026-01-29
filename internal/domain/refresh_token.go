package domain

import "time"

type RefreshToken struct {
	UserID     int64
	DeviceID   string
	TokenHash  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	UserAgent  string
	IP         string
	Revoked    bool
}
