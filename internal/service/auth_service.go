package service

import (
	"central-auth/internal/repository"
	"central-auth/internal/token"
	"time"
)

type AuthService struct {
	redisRepo *repository.RedisRepository
}

func NewAuthService(redisRepo *repository.RedisRepository) *AuthService {
	return &AuthService{redisRepo: redisRepo}
}

func (s *AuthService) Login(userID, deviceID string) (string, string, error) {
	accessToken, err := token.Generate(userID, deviceID, time.Minute*15)
	if err != nil {
		return "", "", err
	}
	
	refreshToken, err := token.Generate(userID, deviceID, time.Hour*24*7)
	if err != nil {
		return "", "", err
	}

	err = s.redisRepo.SaveLogin(userID, deviceID, refreshToken, time.Hour*24*7)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}