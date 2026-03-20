package domain

import "time"

// DeviceSession is the application-level record of an authenticated device session.
// It is an audit log only — Ory Hydra owns the actual token lifecycle.
// Ory Kratos owns the identity (KratosID is the Kratos identity.id UUID).
type DeviceSession struct {
	ID          int64
	KratosID    string
	DeviceID    string
	HydraJTI    *string    // access token JTI at issuance time, for correlation
	IssuedAt    time.Time
	LastUsedAt  *time.Time
	Revoked     bool
	UserAgent   *string
	IP          *string
}
