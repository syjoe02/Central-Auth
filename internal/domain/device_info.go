package domain

import "time"

type LoginDeviceInfo struct {
	DeviceID   string
	UserAgent  string
	IPAddress  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	Revoked    bool
}
