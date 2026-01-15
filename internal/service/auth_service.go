package service

import (
	"central-auth/internal/repository"
	"central-auth/internal/token"
	"errors"
	"time"

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
func (s *AuthService) Login(userID, deviceID string, rememberMe bool) (string, string, error) {
	accessToken, err := token.Generate(userID, deviceID, time.Minute*15)
	if err != nil {
		return "", "", err
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	refreshToken, err := token.Generate(userID, deviceID, refreshTTL)
	if err != nil {
		return "", "", err
	}

	if err := s.redisRepo.SaveLogin(userID, deviceID, refreshToken, refreshTTL); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// OAuth Login
func (s *AuthService) OAuthLogin(
	provider string,
	providerUserID string,
	email string,
	deviceID string,
	rememberMe bool,
) (string, string, error) {

	user, err := s.authUserRepo.FindByProvider(provider, providerUserID)
	if err != nil {
		user = &repository.AuthUser{
			UserID:         uuid.NewString(),
			Provider:       provider,
			ProviderUserID: providerUserID,
			Email:          email,
		}
		if err := s.authUserRepo.Create(user); err != nil {
			return "", "", err
		}
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	accessToken, err := token.Generate(user.UserID, deviceID, AccessTokenTTL)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := token.Generate(user.UserID, deviceID, refreshTTL)
	if err != nil {
		return "", "", err
	}

	if err := s.redisRepo.SaveLogin(
		user.UserID,
		deviceID,
		refreshToken,
		refreshTTL,
	); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) Logout(accessToken string) error {
	claims, err := token.Parse(accessToken)
	if err != nil {
		return err
	}

	if claims.UserID == "" || claims.DeviceID == "" {
		return errors.New("missing claims")
	}
	return s.redisRepo.LogoutDevice(claims.UserID, claims.DeviceID)
}

func (s *AuthService) LogoutAll(accessToken string) error {
	claims, err := token.Parse(accessToken)
	if err != nil {
		return err
	}

	if claims.UserID == "" {
		return errors.New("missing user_id")
	}
	return s.redisRepo.LogoutAll(claims.UserID)
}

func (s *AuthService) Refresh(refreshToken string) (string, error) {
	claims, err := token.Parse(refreshToken)
	if err != nil {
		return "", err
	}

	userID := claims.UserID
	deviceID := claims.DeviceID

	exists, err := s.redisRepo.ExistsRefreshToken(userID, deviceID)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", errors.New("refresh token expired or revoked")
	}

	newAccessToken, err := token.Generate(userID, deviceID, AccessTokenTTL)
	if err != nil {
		return "", err
	}

	return newAccessToken, nil
}
