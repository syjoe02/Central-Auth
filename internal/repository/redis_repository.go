package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const MaxDevices int64 = 5

// RedisRepo defines session-enforcement operations backed by Redis.
// After migration to Ory, Redis is responsible for:
//   - Atomically enforcing the max-5-device limit on login (Lua script).
//   - Storing the current Hydra refresh token per device (for targeted logout).
//   - Device set management (add on login, remove on logout).
type RedisRepo interface {
	SaveLogin(ctx context.Context, kratosID, deviceID, hydraRefreshToken string, ttl time.Duration) error
	GetDeviceRefreshToken(ctx context.Context, kratosID, deviceID string) (string, error)
	RotateRefreshToken(ctx context.Context, kratosID, deviceID, newToken string, ttl time.Duration) error
	LogoutDevice(ctx context.Context, kratosID, deviceID string) error
	LogoutAll(ctx context.Context, kratosID string) error
}

// RedisRepository implements RedisRepo using go-redis.
type RedisRepository struct {
	client *redis.Client
}

// NewRedisRepository creates a new RedisRepository.
func NewRedisRepository(client *redis.Client) *RedisRepository {
	return &RedisRepository{client: client}
}

func devicesKey(kratosID string) string {
	return "auth:devices:" + kratosID
}

func refreshKey(kratosID, deviceID string) string {
	return "auth:refresh:" + kratosID + ":" + deviceID
}

// saveLoginScript atomically enforces the MaxDevices cap and registers the login.
//
// KEYS[1] = devicesKey  (auth:devices:<kratosID>)
// KEYS[2] = refreshKey  (auth:refresh:<kratosID>:<deviceID>)
// ARGV[1] = deviceID member string
// ARGV[2] = login timestamp (unix seconds, float string)
// ARGV[3] = Hydra refresh token value
// ARGV[4] = TTL in seconds (integer string)
// ARGV[5] = max devices limit (integer string)
// ARGV[6] = refresh key prefix (auth:refresh:<kratosID>:)
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

// SaveLogin atomically enforces the max-device cap and stores the Hydra refresh token.
// If the identity already has MaxDevices active devices, the oldest is evicted.
func (r *RedisRepository) SaveLogin(ctx context.Context, kratosID, deviceID, hydraRefreshToken string, ttl time.Duration) error {
	ttlSec := int64(ttl.Seconds())
	rPrefix := "auth:refresh:" + kratosID + ":"
	return saveLoginScript.Run(ctx, r.client,
		[]string{devicesKey(kratosID), refreshKey(kratosID, deviceID)},
		deviceID,
		float64(time.Now().Unix()),
		hydraRefreshToken,
		ttlSec,
		MaxDevices,
		rPrefix,
	).Err()
}

// ErrDeviceTokenNotFound is returned by GetDeviceRefreshToken when no token
// exists for the given kratosID+deviceID pair (device never logged in, or logged out).
var ErrDeviceTokenNotFound = errors.New("device refresh token not found")

// GetDeviceRefreshToken retrieves the stored Hydra refresh token for a specific device.
// Used by the Logout flow to revoke the exact refresh token without an extra introspection call.
// Returns ErrDeviceTokenNotFound when the key is absent (device logged out or never logged in).
func (r *RedisRepository) GetDeviceRefreshToken(ctx context.Context, kratosID, deviceID string) (string, error) {
	token, err := r.client.Get(ctx, refreshKey(kratosID, deviceID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrDeviceTokenNotFound
	}
	return token, err
}

// RotateRefreshToken overwrites the stored Hydra refresh token and resets the TTL.
// Called on /auth/refresh — the old token becomes invalid in Hydra automatically.
func (r *RedisRepository) RotateRefreshToken(ctx context.Context, kratosID, deviceID, newToken string, ttl time.Duration) error {
	return r.client.Set(ctx, refreshKey(kratosID, deviceID), newToken, ttl).Err()
}

// logoutDeviceScript atomically removes a single device from the user's device
// ZSET and deletes its stored Hydra refresh token.
//
// Using Lua instead of a pipeline ensures both operations execute as a single
// atomic unit in Redis, with no window between ZREM and DEL where a concurrent
// login could observe an inconsistent state (device gone from ZSET but token still present).
//
// KEYS[1] = devicesKey  (auth:devices:<kratosID>)
// KEYS[2] = refreshKey  (auth:refresh:<kratosID>:<deviceID>)
// ARGV[1] = deviceID member string
// Returns the number of members removed from the ZSET (0 = device was not active).
var logoutDeviceScript = redis.NewScript(`
local removed = redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('DEL', KEYS[2])
return removed
`)

// LogoutDevice atomically removes the device from the devices ZSET and deletes
// the stored refresh token via a Lua script, ensuring consistency under concurrent logins.
func (r *RedisRepository) LogoutDevice(ctx context.Context, kratosID, deviceID string) error {
	return logoutDeviceScript.Run(ctx, r.client,
		[]string{devicesKey(kratosID), refreshKey(kratosID, deviceID)},
		deviceID,
	).Err()
}

// logoutAllChunkSize is the maximum number of DEL commands sent per pipeline
// batch in LogoutAll. Keeping batches small prevents Redis from blocking on a
// single MULTI/EXEC transaction while a user has many active devices.
const logoutAllChunkSize = 50

// LogoutAll removes all device entries and their refresh tokens for the identity.
// Refresh token DELs are issued in chunks of logoutAllChunkSize via non-transactional
// pipelines to prevent Redis blocking on large device sets. The device ZSET key is
// deleted last, after all token DELs have succeeded, to maintain a consistent state.
func (r *RedisRepository) LogoutAll(ctx context.Context, kratosID string) error {
	dKey := devicesKey(kratosID)
	deviceIDs, err := r.client.ZRange(ctx, dKey, 0, -1).Result()
	if err != nil {
		return err
	}
	// Delete refresh tokens in chunks to prevent Redis blocking on large device sets.
	for i := 0; i < len(deviceIDs); i += logoutAllChunkSize {
		end := i + logoutAllChunkSize
		if end > len(deviceIDs) {
			end = len(deviceIDs)
		}
		pipe := r.client.Pipeline()
		for _, deviceID := range deviceIDs[i:end] {
			pipe.Del(ctx, refreshKey(kratosID, deviceID))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("LogoutAll: chunk %d-%d: %w", i, end, err)
		}
	}
	// Delete the ZSET after all tokens are gone.
	return r.client.Del(ctx, dKey).Err()
}
