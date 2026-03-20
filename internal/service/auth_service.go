package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"central-auth/internal/domain"
	"central-auth/internal/hydra"
	"central-auth/internal/repository"
)

const (
	RefreshTTLShort = time.Hour * 24 * 7  // 7 days (default)
	RefreshTTLLong  = time.Hour * 24 * 30 // 30 days (remember_me)
)

// ErrInvalidToken is returned by the service for token errors that should map
// to HTTP 401 on the caller side (bad token, expired, wrong type).
var ErrInvalidToken = errors.New("invalid or expired token")

// VerifyResult holds the validated claims extracted from a Hydra access token.
type VerifyResult struct {
	KratosID  string
	DeviceID  string
	ExpiresAt int64
}

// AuthServiceI is the interface that wraps all auth business logic operations.
// It is satisfied by both OryAuthService (real) and InstrumentedAuthService (metrics wrapper).
type AuthServiceI interface {
	// Login issues Hydra tokens for a pre-authenticated Kratos identity.
	// The caller (e.g. Django) has already verified the user's credentials.
	Login(ctx context.Context, kratosID, deviceID string, rememberMe bool, userAgent, ip *string) (accessToken, refreshToken string, err error)

	// Logout revokes the session identified by the given Hydra refresh token.
	Logout(ctx context.Context, refreshToken string) error

	// LogoutAll revokes all sessions for the user identified by the given Hydra refresh token.
	LogoutAll(ctx context.Context, refreshToken string) error

	// Refresh exchanges a Hydra refresh token for a new access+refresh token pair.
	Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)

	// VerifyToken validates a Hydra access token JWT and returns its claims.
	// Fail-closed: any error (invalid signature, expired, JWKS unavailable) returns a non-nil error.
	VerifyToken(ctx context.Context, accessToken string) (*VerifyResult, error)
}

// OryAuthService implements AuthServiceI using Ory Hydra for token management
// and Redis for atomic device-session enforcement.
type OryAuthService struct {
	hydra             hydra.ClientI
	redisRepo         repository.RedisRepo
	deviceSessionRepo repository.DeviceSessionRepository
}

// NewOryAuthService creates a new OryAuthService.
func NewOryAuthService(
	hydraClient hydra.ClientI,
	redisRepo repository.RedisRepo,
	deviceSessionRepo repository.DeviceSessionRepository,
) *OryAuthService {
	return &OryAuthService{
		hydra:             hydraClient,
		redisRepo:         redisRepo,
		deviceSessionRepo: deviceSessionRepo,
	}
}

// Login issues Hydra tokens for a Kratos identity.
//
// Flow:
//  1. Programmatic Hydra authorization code flow → access + refresh tokens
//  2. Redis atomic Lua script enforces max-5-device limit (evicts oldest if needed)
//  3. device_sessions audit row is upserted in Postgres
func (s *OryAuthService) Login(
	ctx context.Context,
	kratosID, deviceID string,
	rememberMe bool,
	userAgent, ip *string,
) (string, string, error) {
	log.Printf("[AUTH] Login start kratosID=%s device=%s", kratosID, deviceID)

	tokens, err := s.hydra.IssueTokens(ctx, kratosID, deviceID, rememberMe)
	if err != nil {
		log.Printf("[ERROR] Hydra IssueTokens failed: %+v", err)
		return "", "", fmt.Errorf("login: issue tokens: %w", err)
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	if err := s.redisRepo.SaveLogin(ctx, kratosID, deviceID, tokens.RefreshToken, refreshTTL); err != nil {
		log.Printf("[ERROR] Redis SaveLogin failed: %+v", err)
		return "", "", fmt.Errorf("login: save session: %w", err)
	}

	now := time.Now()
	if err := s.deviceSessionRepo.SaveDeviceSession(ctx, &domain.DeviceSession{
		KratosID:  kratosID,
		DeviceID:  deviceID,
		IssuedAt:  now,
		UserAgent: userAgent,
		IP:        ip,
		Revoked:   false,
	}); err != nil {
		log.Printf("[ERROR] Postgres SaveDeviceSession failed: %+v", err)
		return "", "", fmt.Errorf("login: save device session: %w", err)
	}

	log.Printf("[AUTH] Login success kratosID=%s device=%s", kratosID, deviceID)
	return tokens.AccessToken, tokens.RefreshToken, nil
}

// Logout revokes the session for the device identified by the Hydra refresh token.
//
// Flow:
//  1. Introspect the refresh token via Hydra Admin API → extract kratosID + deviceID
//  2. Revoke the token in Hydra (invalidates associated access tokens too)
//  3. Remove the device from Redis
//  4. Mark the device_sessions row as revoked in Postgres
func (s *OryAuthService) Logout(ctx context.Context, refreshToken string) error {
	log.Printf("[AUTH] Logout start")

	introspect, err := s.hydra.IntrospectToken(ctx, refreshToken)
	if err != nil {
		log.Printf("[ERROR] Hydra IntrospectToken failed: %+v", err)
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !introspect.Active {
		return fmt.Errorf("%w: token is inactive", ErrInvalidToken)
	}

	kratosID := introspect.Subject
	deviceID := introspect.DeviceID()
	if kratosID == "" || deviceID == "" {
		log.Printf("[ERROR] Logout: missing claims kratosID=%q deviceID=%q", kratosID, deviceID)
		return fmt.Errorf("%w: missing subject or device_id in token", ErrInvalidToken)
	}

	if err := s.hydra.RevokeToken(ctx, refreshToken); err != nil {
		log.Printf("[ERROR] Hydra RevokeToken failed: %+v", err)
		return fmt.Errorf("logout: revoke token: %w", err)
	}

	if err := s.redisRepo.LogoutDevice(ctx, kratosID, deviceID); err != nil {
		log.Printf("[WARN] logout: Redis cleanup failed (non-fatal): %v", err)
	}

	if err := s.deviceSessionRepo.RevokeDevice(ctx, kratosID, deviceID); err != nil {
		log.Printf("[WARN] logout: Postgres revoke failed (non-fatal): %v", err)
	}

	log.Printf("[AUTH] Logout success kratosID=%s device=%s", kratosID, deviceID)
	return nil
}

// LogoutAll revokes all sessions for the user identified by the Hydra refresh token.
//
// Flow:
//  1. Introspect the refresh token → extract kratosID
//  2. Hydra Admin API: delete all tokens for the subject
//  3. Redis: remove all device entries
//  4. Postgres: mark all device_sessions rows as revoked
func (s *OryAuthService) LogoutAll(ctx context.Context, refreshToken string) error {
	log.Printf("[AUTH] LogoutAll start")

	introspect, err := s.hydra.IntrospectToken(ctx, refreshToken)
	if err != nil {
		log.Printf("[ERROR] Hydra IntrospectToken failed: %+v", err)
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !introspect.Active {
		return fmt.Errorf("%w: token is inactive", ErrInvalidToken)
	}

	kratosID := introspect.Subject
	if kratosID == "" {
		return fmt.Errorf("%w: missing subject in token", ErrInvalidToken)
	}

	if err := s.hydra.RevokeAllForSubject(ctx, kratosID); err != nil {
		log.Printf("[ERROR] Hydra RevokeAllForSubject failed: %+v", err)
		return fmt.Errorf("logout all: revoke tokens: %w", err)
	}

	if err := s.redisRepo.LogoutAll(ctx, kratosID); err != nil {
		log.Printf("[WARN] logout all: Redis cleanup failed (non-fatal): %v", err)
	}

	if err := s.deviceSessionRepo.RevokeAllDevices(ctx, kratosID); err != nil {
		log.Printf("[WARN] logout all: Postgres revoke failed (non-fatal): %v", err)
	}

	log.Printf("[AUTH] LogoutAll success kratosID=%s", kratosID)
	return nil
}

// Refresh exchanges a Hydra refresh token for a new access+refresh token pair.
//
// Flow:
//  1. Call Hydra token endpoint with grant_type=refresh_token
//  2. Parse the new access token JWT to extract kratosID and deviceID
//  3. Update Redis with the new refresh token (old token is now invalid in Hydra)
//  4. Update device_sessions.last_used_at
func (s *OryAuthService) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	log.Printf("[AUTH] Refresh start")

	tokens, err := s.hydra.RefreshToken(ctx, refreshToken)
	if err != nil {
		log.Printf("[ERROR] Hydra RefreshToken failed: %+v", err)
		return "", "", fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	// Parse the new access token to get kratosID and deviceID for cleanup.
	claims, err := s.hydra.ValidateAccessToken(ctx, tokens.AccessToken)
	if err != nil {
		log.Printf("[ERROR] Parse new access token failed: %+v", err)
		return "", "", fmt.Errorf("refresh: parse new access token: %w", err)
	}

	kratosID := claims.Subject
	deviceID := claims.DeviceID()

	if err := s.redisRepo.RotateRefreshToken(ctx, kratosID, deviceID, tokens.RefreshToken, RefreshTTLLong); err != nil {
		log.Printf("[WARN] refresh: Redis rotate failed (non-fatal): %v", err)
	}

	if err := s.deviceSessionRepo.UpdateLastUsedAt(ctx, kratosID, deviceID); err != nil {
		log.Printf("[WARN] refresh: Postgres update last_used_at failed (non-fatal): %v", err)
	}

	log.Printf("[AUTH] Refresh success kratosID=%s device=%s", kratosID, deviceID)
	return tokens.AccessToken, tokens.RefreshToken, nil
}

// VerifyToken validates a Hydra JWT access token locally using JWKS.
// Fail-closed: any error causes the caller to return HTTP 401.
func (s *OryAuthService) VerifyToken(ctx context.Context, accessToken string) (*VerifyResult, error) {
	claims, err := s.hydra.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	deviceID := claims.DeviceID()
	if claims.Subject == "" || deviceID == "" {
		return nil, errors.New("missing subject or device_id in token")
	}
	var exp int64
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	return &VerifyResult{
		KratosID:  claims.Subject,
		DeviceID:  deviceID,
		ExpiresAt: exp,
	}, nil
}

// compile-time interface check
var _ AuthServiceI = (*OryAuthService)(nil)
