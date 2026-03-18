package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"central-auth/internal/domain"
	"central-auth/internal/repository"
	"central-auth/internal/token"

	"github.com/google/uuid"
)

const (
	AccessTokenTTL  = time.Minute * 15
	RefreshTTLShort = time.Hour * 24 * 7
	RefreshTTLLong  = time.Hour * 24 * 30
)

// AuthServiceI is the interface that wraps the auth business logic operations.
type AuthServiceI interface {
	Login(ctx context.Context, userID, deviceID string, rememberMe bool, userAgent, ip *string) (string, string, error)
	OAuthLogin(ctx context.Context, provider, providerID, email, deviceID string, rememberMe bool, userAgent, ip *string) (string, string, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, refreshToken string) error
	Refresh(ctx context.Context, refreshToken string) (string, string, error)
	ExistsSession(ctx context.Context, userID, deviceID string) (bool, error)
}

type AuthService struct {
	redisRepo    repository.RedisRepo
	authUserRepo repository.AuthUserRepository
}

func NewAuthService(
	redisRepo repository.RedisRepo,
	authUserRepo repository.AuthUserRepository,
) *AuthService {
	return &AuthService{redisRepo: redisRepo, authUserRepo: authUserRepo}
}

// accessToken : 15min, refreshToken : 7 days, rememberMe : 30 days
func (s *AuthService) Login(ctx context.Context, userID string, deviceID string, rememberMe bool, userAgent *string, ip *string) (string, string, error) {
	log.Printf("[AUTH] Login start user=%s device=%s", userID, deviceID)

	accessToken, err := token.Generate(userID, deviceID, token.TypeAccess, AccessTokenTTL)
	if err != nil {
		return "", "", err
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	refreshToken, err := token.Generate(userID, deviceID, token.TypeRefresh, refreshTTL)
	if err != nil {
		log.Printf("[ERROR] Generate refresh token failed: %+v", err)
		return "", "", err
	}

	if err := s.redisRepo.SaveLogin(ctx, userID, deviceID, refreshToken, refreshTTL); err != nil {
		log.Printf("[ERROR] Redis SaveLogin failed: %+v", err)
		return "", "", fmt.Errorf("login: save session: %w", err)
	}

	now := time.Now()
	err = s.authUserRepo.SaveRefreshToken(ctx, &domain.RefreshToken{
		UserID:     userID,
		DeviceID:   deviceID,
		TokenHash:  token.Hash(refreshToken),
		IssuedAt:   now,
		ExpiresAt:  now.Add(refreshTTL),
		LastUsedAt: nil,
		UserAgent:  userAgent,
		IP:         ip,
		Revoked:    false,
	})
	if err != nil {
		log.Printf("[ERROR] Postgres SaveRefreshToken failed: %+v", err)
		return "", "", fmt.Errorf("login: save token record: %w", err)
	}

	log.Printf("[AUTH] Login success user=%s device=%s", userID, deviceID)
	return accessToken, refreshToken, nil
}

// OAuthLogin verifies the provider token, upserts the user, and issues tokens.
func (s *AuthService) OAuthLogin(
	ctx context.Context,
	provider string,
	providerID string,
	email string,
	deviceID string,
	rememberMe bool,
	userAgent *string,
	ip *string,
) (string, string, error) {

	log.Printf("[AUTH] OAuthLogin start provider=%s providerID=%s device=%s",
		provider, providerID, deviceID)

	user, err := s.authUserRepo.FindByProvider(ctx, provider, providerID)
	if err != nil {
		log.Printf("[ERROR] FindByProvider failed: %+v", err)
		return "", "", err
	}

	if user == nil {
		log.Printf("[AUTH] Creating new AuthUser for provider=%s id=%s", provider, providerID)
		user = &domain.AuthUser{
			UserID:     uuid.NewString(),
			Provider:   provider,
			ProviderID: providerID,
			Email:      email,
		}
		if err := s.authUserRepo.Save(ctx, user); err != nil {
			log.Printf("[ERROR] Save AuthUser failed: %+v", err)
			return "", "", err
		}
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	accessToken, err := token.Generate(user.UserID, deviceID, token.TypeAccess, AccessTokenTTL)
	if err != nil {
		log.Printf("[ERROR] Generate access token failed: %+v", err)
		return "", "", err
	}

	refreshToken, err := token.Generate(user.UserID, deviceID, token.TypeRefresh, refreshTTL)
	if err != nil {
		log.Printf("[ERROR] Generate refresh token failed: %+v", err)
		return "", "", err
	}

	if err := s.redisRepo.SaveLogin(ctx, user.UserID, deviceID, refreshToken, refreshTTL); err != nil {
		log.Printf("[ERROR] Redis SaveLogin failed: %+v", err)
		return "", "", fmt.Errorf("oauth login: save session: %w", err)
	}

	now := time.Now()
	err = s.authUserRepo.SaveRefreshToken(ctx, &domain.RefreshToken{
		UserID:     user.UserID,
		DeviceID:   deviceID,
		TokenHash:  token.Hash(refreshToken),
		IssuedAt:   now,
		ExpiresAt:  now.Add(refreshTTL),
		LastUsedAt: nil,
		UserAgent:  userAgent,
		IP:         ip,
		Revoked:    false,
	})
	if err != nil {
		log.Printf("[ERROR] Postgres SaveRefreshToken failed: %+v", err)
		return "", "", fmt.Errorf("oauth login: save token record: %w", err)
	}

	log.Printf("[AUTH] OAuthLogin success user=%s device=%s", user.UserID, deviceID)
	return accessToken, refreshToken, nil
}

// Logout revokes the session for the device identified by the refresh token.
// Uses ParseIgnoreExpiry so logout succeeds even when the access token is expired —
// Django's JWTAuthentication blocks the request before it reaches Go in that case,
// but this ensures Go is correct if Django's skip_paths is ever updated.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	log.Printf("[AUTH] Logout start")

	claims, err := token.ParseIgnoreExpiry(refreshToken, token.TypeRefresh)
	if err != nil {
		log.Printf("[ERROR] Token parse failed: %+v", err)
		return err
	}

	if claims.UserID == "" || claims.DeviceID == "" {
		log.Printf("[ERROR] Missing claims userID=%s deviceID=%s", claims.UserID, claims.DeviceID)
		return errors.New("missing claims")
	}

	if err := s.redisRepo.LogoutDevice(ctx, claims.UserID, claims.DeviceID); err != nil {
		log.Printf("[ERROR] Redis LogoutDevice failed: %+v", err)
		return fmt.Errorf("logout: revoke session: %w", err)
	}

	if err := s.authUserRepo.RevokeDevice(ctx, claims.UserID, claims.DeviceID); err != nil {
		log.Printf("[ERROR] Postgres RevokeDevice failed: %+v", err)
		return fmt.Errorf("logout: revoke token record: %w", err)
	}

	log.Printf("[AUTH] Logout success user=%s device=%s", claims.UserID, claims.DeviceID)
	return nil
}

// LogoutAll revokes all sessions for the user identified by the refresh token.
func (s *AuthService) LogoutAll(ctx context.Context, refreshToken string) error {
	log.Printf("[AUTH] LogoutAll start")

	claims, err := token.ParseIgnoreExpiry(refreshToken, token.TypeRefresh)
	if err != nil {
		log.Printf("[ERROR] Token parse failed: %+v", err)
		return err
	}

	if claims.UserID == "" {
		log.Printf("[ERROR] Missing user_id in claims")
		return errors.New("missing user_id")
	}

	if err := s.redisRepo.LogoutAll(ctx, claims.UserID); err != nil {
		log.Printf("[ERROR] Redis LogoutAll failed: %+v", err)
		return fmt.Errorf("logout all: revoke sessions: %w", err)
	}

	if err := s.authUserRepo.RevokeAllDevices(ctx, claims.UserID); err != nil {
		log.Printf("[ERROR] Postgres RevokeAllDevices failed: %+v", err)
		return fmt.Errorf("logout all: revoke token records: %w", err)
	}

	log.Printf("[AUTH] LogoutAll success user=%s", claims.UserID)
	return nil
}

// Refresh validates the refresh token, rotates it, and returns a new access + refresh token pair.
// The old refresh token is invalidated in Redis immediately — any replay of the old token is rejected.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	log.Printf("[AUTH] Refresh start")

	claims, err := token.ParseTyped(refreshToken, token.TypeRefresh)
	if err != nil {
		log.Printf("[ERROR] Token parse failed: %+v", err)
		return "", "", err
	}

	userID := claims.UserID
	deviceID := claims.DeviceID

	// Validate token value against Redis — rejects previous-generation tokens after rotation
	valid, err := s.redisRepo.ValidateRefreshToken(ctx, userID, deviceID, refreshToken)
	if err != nil {
		log.Printf("[ERROR] Redis ValidateRefreshToken failed: %+v", err)
		return "", "", err
	}
	if !valid {
		log.Printf("[WARN] Refresh token invalid or rotated user=%s device=%s", userID, deviceID)
		return "", "", errors.New("refresh token expired or revoked")
	}

	// Determine TTL from remaining lifetime of the current token
	refreshTTL := time.Until(claims.ExpiresAt.Time)
	if refreshTTL <= 0 {
		return "", "", errors.New("refresh token expired")
	}

	newAccessToken, err := token.Generate(userID, deviceID, token.TypeAccess, AccessTokenTTL)
	if err != nil {
		log.Printf("[ERROR] Generate new access token failed: %+v", err)
		return "", "", err
	}

	newRefreshToken, err := token.Generate(userID, deviceID, token.TypeRefresh, refreshTTL)
	if err != nil {
		log.Printf("[ERROR] Generate new refresh token failed: %+v", err)
		return "", "", err
	}

	// Overwrite Redis with the new token — old token string is now invalid
	if err := s.redisRepo.RotateRefreshToken(ctx, userID, deviceID, newRefreshToken, refreshTTL); err != nil {
		log.Printf("[ERROR] Redis RotateRefreshToken failed: %+v", err)
		return "", "", fmt.Errorf("refresh: rotate session: %w", err)
	}

	// Update Postgres hash + last_used_at in one query
	if err := s.authUserRepo.UpdateTokenHash(ctx, userID, deviceID, token.Hash(newRefreshToken)); err != nil {
		log.Printf("[ERROR] Postgres UpdateTokenHash failed: %+v", err)
		return "", "", fmt.Errorf("refresh: update token record: %w", err)
	}

	log.Printf("[AUTH] Refresh success user=%s device=%s", userID, deviceID)
	return newAccessToken, newRefreshToken, nil
}

// ExistsSession checks whether a live session exists in Redis for the given user+device.
// Used by /auth/verify — only needs existence, not token value validation.
func (s *AuthService) ExistsSession(ctx context.Context, userID, deviceID string) (bool, error) {
	exists, err := s.redisRepo.ExistsRefreshToken(ctx, userID, deviceID)
	if err != nil {
		log.Printf("[ERROR] ExistsSession Redis check failed: %+v", err)
	}
	return exists, err
}
