package repository

import (
	"central-auth/internal/config"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisRepository struct {
	client *redis.Client
}

func NewRedisRepository(client *redis.Client) *RedisRepository {
	return &RedisRepository{client: client}
}

func (r *RedisRepository) SaveLogin(userID, deviceID, refreshToken string, ttl time.Duration) error {
	ctx := config.Ctx

	r.client.Del(ctx, "auth:refresh:"+userID)
	r.client.Del(ctx, "auth:device:"+userID)

	if err := r.client.Set(ctx, "auth:refresh:"+userID, refreshToken, ttl).Err(); err != nil {
		return err
	}
	if err := r.client.Set(ctx, "auth:device:"+userID, deviceID, ttl).Err(); err != nil {
		return err
	}
	return nil
}