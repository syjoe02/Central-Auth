package repository

import (
	"context"

	"central-auth/internal/domain"
)

type AuthUserRepository interface {
	// AuthUser
	FindByProvider(provider, providerID string) (*domain.AuthUser, error)
	Save(user *domain.AuthUser) error

	// Refresh Token
	SaveRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	UpdateLastUsedAt(ctx context.Context, userID string, deviceID string) error
	RevokeDevice(ctx context.Context, userID string, deviceID string) error
	RevokeAllDevices(ctx context.Context, userID string) error

	GetLoginDevices(ctx context.Context, userID string) ([]domain.LoginDeviceInfo, error)
	CountActiveDevices(ctx context.Context, userID string) (int, error)
}
