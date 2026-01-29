package service

import (
	"context"
	"errors"
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

type AuthService struct {
	redisRepo    *repository.RedisRepository
	authUserRepo repository.AuthUserRepository
}

func NewAuthService(
	redisRepo *repository.RedisRepository,
	authUserRepo repository.AuthUserRepository,
) *AuthService {
	return &AuthService{redisRepo: redisRepo, authUserRepo: authUserRepo}
}

// accessToken : 15min, refreshToken : 7 days, rememberMe : 30 days
func (s *AuthService) Login(userID string, deviceID string, rememberMe bool, userAgent *string, ip *string) (string, string, error) {
	log.Printf("[AUTH] Login start user=%s device=%s", userID, deviceID)
	accessToken, err := token.Generate(userID, deviceID, AccessTokenTTL)
	if err != nil {
		return "", "", err
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	refreshToken, err := token.Generate(userID, deviceID, refreshTTL)
	if err != nil {
		log.Printf("[ERROR] Generate refresh token failed: %+v", err)
		return "", "", err
	}

	if err := s.redisRepo.SaveLogin(userID, deviceID, refreshToken, refreshTTL); err != nil {
		log.Printf("[ERROR] Redis SaveLogin failed: %+v", err)
		return "", "", err
	}

	// stored postgres
	now := time.Now()
	err = s.authUserRepo.SaveRefreshToken(context.Background(), &domain.RefreshToken{
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
		return "", "", err
	}
	log.Printf("[AUTH] Login success user=%s device=%s", userID, deviceID)
	return accessToken, refreshToken, nil
}

// OAuth Login
func (s *AuthService) OAuthLogin(
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

	user, err := s.authUserRepo.FindByProvider(provider, providerID)
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
		if err := s.authUserRepo.Save(user); err != nil {
			log.Printf("[ERROR] Save AuthUser failed: %+v", err)
			return "", "", err
		}
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	accessToken, err := token.Generate(user.UserID, deviceID, AccessTokenTTL)
	if err != nil {
		log.Printf("[ERROR] Generate access token failed: %+v", err)
		return "", "", err
	}

	refreshToken, err := token.Generate(user.UserID, deviceID, refreshTTL)
	if err != nil {
		log.Printf("[ERROR] Generate refresh token failed: %+v", err)
		return "", "", err
	}

	// redis
	if err := s.redisRepo.SaveLogin(
		user.UserID,
		deviceID,
		refreshToken,
		refreshTTL,
	); err != nil {
		log.Printf("[ERROR] Redis SaveLogin failed: %+v", err)
		return "", "", err
	}
	// postgres
	now := time.Now()
	err = s.authUserRepo.SaveRefreshToken(context.Background(), &domain.RefreshToken{
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
		return "", "", err
	}
	log.Printf("[AUTH] OAuthLogin success user=%s device=%s", user.UserID, deviceID)
	return accessToken, refreshToken, nil
}

func (s *AuthService) Logout(accessToken string) error {
	log.Printf("[AUTH] Logout start")

	claims, err := token.Parse(accessToken)
	if err != nil {
		log.Printf("[ERROR] Token parse failed: %+v", err)
		return err
	}

	if claims.UserID == "" || claims.DeviceID == "" {
		log.Printf("[ERROR] Missing claims userID=%s deviceID=%s", claims.UserID, claims.DeviceID)
		return errors.New("missing claims")
	}

	// redis
	if err := s.redisRepo.LogoutDevice(claims.UserID, claims.DeviceID); err != nil {
		log.Printf("[ERROR] Redis LogoutDevice failed: %+v", err)
		return err
	}
	// postgres
	if err := s.authUserRepo.RevokeDevice(
		context.Background(),
		claims.UserID,
		claims.DeviceID,
	); err != nil {
		log.Printf("[ERROR] Postgres RevokeDevice failed: %+v", err)
		return err
	}

	log.Printf("[AUTH] Logout success user=%s device=%s", claims.UserID, claims.DeviceID)
	return nil
}

func (s *AuthService) LogoutAll(accessToken string) error {
	log.Printf("[AUTH] LogoutAll start")

	claims, err := token.Parse(accessToken)
	if err != nil {
		log.Printf("[ERROR] Token parse failed: %+v", err)
		return err
	}

	if claims.UserID == "" {
		log.Printf("[ERROR] Missing user_id in claims")
		return errors.New("missing user_id")
	}

	// Redis
	if err := s.redisRepo.LogoutAll(claims.UserID); err != nil {
		log.Printf("[ERROR] Redis LogoutAll failed: %+v", err)
		return err
	}
	// Postgres
	if err := s.authUserRepo.RevokeAllDevices(
		context.Background(),
		claims.UserID,
	); err != nil {
		log.Printf("[ERROR] Postgres RevokeAllDevices failed: %+v", err)
		return err
	}

	log.Printf("[AUTH] LogoutAll success user=%s", claims.UserID)
	return nil
}

func (s *AuthService) Refresh(refreshToken string) (string, error) {
	log.Printf("[AUTH] Refresh start")

	claims, err := token.Parse(refreshToken)
	if err != nil {
		log.Printf("[ERROR] Token parse failed: %+v", err)
		return "", err
	}

	userID := claims.UserID
	deviceID := claims.DeviceID

	exists, err := s.redisRepo.ExistsRefreshToken(userID, deviceID)
	if err != nil {
		log.Printf("[ERROR] Redis ExistsRefreshToken failed: %+v", err)
		return "", err
	}
	if !exists {
		log.Printf("[WARN] Refresh token not found user=%s device=%s", userID, deviceID)
		return "", errors.New("refresh token expired or revoked")
	}

	// postgres
	if err := s.authUserRepo.UpdateLastUsedAt(context.Background(), userID, deviceID); err != nil {
		log.Printf("[ERROR] Postgres UpdateLastUsedAt failed: %+v", err)
		return "", err
	}

	newAccessToken, err := token.Generate(userID, deviceID, AccessTokenTTL)
	if err != nil {
		log.Printf("[ERROR] Generate new access token failed: %+v", err)
		return "", err
	}

	log.Printf("[AUTH] Refresh success user=%s device=%s", userID, deviceID)
	return newAccessToken, nil
}

func (s *AuthService) ExistsSession(userID, deviceID string) (bool, error) {
	exists, err := s.redisRepo.ExistsRefreshToken(userID, deviceID)
	if err != nil {
		log.Printf("[ERROR] ExistsSession Redis check failed: %+v", err)
	}
	return exists, err
}
