package service

import (
	"central-auth/internal/repository"
	"central-auth/internal/token"
	"time"

	"github.com/google/uuid"
)

const (
	AccessTokenTTL  = time.Minute * 15
	RefreshTTLShort = time.Hour * 24 * 7
	RefreshTTLLong  = time.Hour * 24 * 30 
)

type AuthService struct {
	redisRepo *repository.RedisRepository
	authUserRepo repository.AuthUserRepository
}

func NewAuthService(
	redisRepo *repository.RedisRepository,
	authUserRepo repository.AuthUserRepository,
	) *AuthService {
	return &AuthService{redisRepo: redisRepo, authUserRepo: authUserRepo,}
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

	// 1. Central-Auth DB에서 내부 userId 조회 or 생성
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