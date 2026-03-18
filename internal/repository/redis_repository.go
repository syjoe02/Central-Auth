package repository

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const MaxDevices int64 = 5

// RedisRepo is the interface that wraps session storage operations.
type RedisRepo interface {
	SaveLogin(ctx context.Context, userID, deviceID, refreshToken string, ttl time.Duration) error
	ExistsRefreshToken(ctx context.Context, userID, deviceID string) (bool, error)
	ValidateRefreshToken(ctx context.Context, userID, deviceID, tokenStr string) (bool, error)
	RotateRefreshToken(ctx context.Context, userID, deviceID, newToken string, ttl time.Duration) error
	LogoutDevice(ctx context.Context, userID, deviceID string) error
	LogoutAll(ctx context.Context, userID string) error
}

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


// saveLoginScript atomically enforces the MaxDevices cap and registers the login.
//
// KEYS[1] = devicesKey (auth:devices:<userID>)
// KEYS[2] = refreshKey for this device (auth:refresh:<userID>:<deviceID>)
// ARGV[1] = deviceID member string
// ARGV[2] = login timestamp (unix seconds, float string)
// ARGV[3] = refresh token value
// ARGV[4] = TTL in seconds (integer string)
// ARGV[5] = max devices limit (integer string)
// ARGV[6] = refresh key prefix  (auth:refresh:<userID>:)
var saveLoginScript = redis.NewScript(`
local dKey      = KEYS[1]
local rKey      = KEYS[2]
local deviceID  = ARGV[1]
local score     = tonumber(ARGV[2])
local tokenVal  = ARGV[3]
local ttl       = tonumber(ARGV[4])
local maxDev    = tonumber(ARGV[5])
local rPrefix   = ARGV[6]

local existing = redis.call('ZSCORE', dKey, deviceID)
if existing == false then
    local count = tonumber(redis.call('ZCARD', dKey))
    if count >= maxDev then
        local oldest = redis.call('ZRANGE', dKey, 0, 0)
        if #oldest > 0 then
            redis.call('ZREM', dKey, oldest[1])
            redis.call('DEL', rPrefix .. oldest[1])
        end
    end
end

redis.call('ZADD', dKey, score, deviceID)
redis.call('SET',  rKey, tokenVal, 'EX', ttl)
local currentTTL = tonumber(redis.call('TTL', dKey))
if currentTTL < 0 or ttl > currentTTL then
    redis.call('EXPIRE', dKey, ttl)
end
return 1
`)

func (r *RedisRepository) SaveLogin(ctx context.Context, userID, deviceID, refreshToken string, ttl time.Duration) error {
	ttlSec := int64(ttl.Seconds())
	rPrefix := "auth:refresh:" + userID + ":"

	return saveLoginScript.Run(ctx, r.client,
		[]string{devicesKey(userID), refreshKey(userID, deviceID)},
		deviceID,
		float64(time.Now().Unix()),
		refreshToken,
		ttlSec,
		MaxDevices,
		rPrefix,
	).Err()
}

// ExistsRefreshToken checks only that the session key is present in Redis.
// Used by /auth/verify — confirm the session is alive without needing the token value.
func (r *RedisRepository) ExistsRefreshToken(ctx context.Context, userID, deviceID string) (bool, error) {
	key := refreshKey(userID, deviceID)
	cnt, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return cnt == 1, nil
}

// ValidateRefreshToken checks that the session key exists AND its stored value matches
// the presented token. Used by /auth/refresh after rotation — rejects any previous-generation token.
func (r *RedisRepository) ValidateRefreshToken(ctx context.Context, userID, deviceID, tokenStr string) (bool, error) {
	stored, err := r.client.Get(ctx, refreshKey(userID, deviceID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return stored == tokenStr, nil
}

// RotateRefreshToken overwrites the stored refresh token value and resets the TTL.
// Called on /auth/refresh — the old token string is implicitly invalidated because
// ValidateRefreshToken will no longer match it.
func (r *RedisRepository) RotateRefreshToken(ctx context.Context, userID, deviceID, newToken string, ttl time.Duration) error {
	return r.client.Set(ctx, refreshKey(userID, deviceID), newToken, ttl).Err()
}

func (r *RedisRepository) LogoutDevice(ctx context.Context, userID, deviceID string) error {
	dKey := devicesKey(userID)
	rKey := refreshKey(userID, deviceID)

	pipe := r.client.TxPipeline()
	pipe.Del(ctx, rKey)
	pipe.ZRem(ctx, dKey, deviceID)

	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRepository) LogoutAll(ctx context.Context, userID string) error {
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