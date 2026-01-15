package repository

import (
	"central-auth/internal/config"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const MaxDevices int64 = 5

type RedisRepository struct {
	client *redis.Client
}

func NewRedisRepository(client *redis.Client) *RedisRepository {
	return &RedisRepository{client: client}
}

func devicesKey(userID string) string {
	return "auth:devices:" + userID
}

func refreshKey(userID, deviceID string) string {
	return "auth:refresh:" + userID + ":" + deviceID
}


func (r *RedisRepository) SaveLogin(userID, deviceID, refreshToken string, ttl time.Duration) error {
	ctx := config.Ctx

	now := float64(time.Now().Unix())
	dKey := devicesKey(userID)

	// checking deviceID
	count, err := r.client.ZCard(ctx, dKey).Result()
	if err != nil {
		return err
	}
	existsScore, err := r.client.ZScore(ctx, dKey, deviceID).Result()
	if err != nil && err != redis.Nil {
		return err
	}

	isExistingDevice := (err == nil && existsScore != 0) || (err == nil) // ZScore returns nil err if exists

	if !isExistingDevice && count >= MaxDevices {
		oldest, err := r.client.ZRangeWithScores(ctx, dKey, 0, 0).Result()
		if err != nil {
			return err
		}
		if len(oldest) == 0 {
			return errors.New("device set empty unexpectedly")
		}

		oldDeviceID, ok := oldest[0].Member.(string)
		if !ok {
			return errors.New("invalid member type in zset")
		}

		// delete oldest deviceID and refreshToken
		pipe := r.client.TxPipeline()
		pipe.ZRem(ctx, dKey, oldDeviceID)
		pipe.Del(ctx, refreshKey(userID, oldDeviceID))
		if _, err := pipe.Exec(ctx); err != nil {
			return err
		}
	}

	if err := r.client.ZAdd(ctx, dKey, redis.Z{Score: now, Member: deviceID}).Err(); err != nil {
		return err
	}

	if err := r.client.Set(ctx, refreshKey(userID, deviceID), refreshToken, ttl).Err(); err != nil {
		return err
	}

	if err := r.client.Expire(ctx, dKey, ttl).Err(); err != nil {
		return err
	}

	return nil
}

func (r *RedisRepository) ExistsRefreshToken(userID, deviceID string) (bool, error) {
	ctx := config.Ctx
	key := "auth:refresh:" + userID + ":" + deviceID
	cnt, err := r.client.Exists(ctx, key).Result()

	if err != nil {
		return false, err
	}
	return cnt == 1, nil
}

func (r *RedisRepository) LogoutDevice(userID, deviceID string) error {
	ctx := config.Ctx
	dKey := devicesKey(userID)
	rKey := refreshKey(userID, deviceID)

	pipe := r.client.TxPipeline()
	pipe.Del(ctx, rKey)
	pipe.ZRem(ctx, dKey, deviceID)

	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRepository) LogoutAll(userID string) error {
	ctx := config.Ctx
	dKey := devicesKey(userID)

	devicesIDs, err := r.client.ZRange(ctx, dKey, 0, -1).Result()
	if err != nil {
		return err
	}

	pipe := r.client.TxPipeline()

	for _, deviceID := range devicesIDs {
		pipe.Del(ctx, refreshKey(userID, deviceID))
	}

	pipe.Del(ctx, dKey)
	_, err = pipe.Exec(ctx)
	return err
}