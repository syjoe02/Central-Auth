package resilience

import (
	"context"
	"fmt"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/repository"
)

// ResilientRedisRepo wraps repository.RedisRepo with circuit-breaker protection
// and an L1 in-process cache for GetDeviceRefreshToken reads.
//
// Fallback hierarchy when the circuit is OPEN:
//   GetDeviceRefreshToken: L1 cache (key = drt:{kratosID}:{deviceID}) → ErrRedisUnavailable.
//   All write operations:  Return ErrRedisUnavailable immediately.
//                          Login and token rotation will fail during Redis outages —
//                          this is the accepted trade-off for atomic device-limit enforcement.
type ResilientRedisRepo struct {
	delegate repository.RedisRepo
	cb       CircuitBreaker
	l1       *gocache.Cache
}

// NewResilientRedisRepo creates the decorator.
func NewResilientRedisRepo(
	delegate repository.RedisRepo,
	cb CircuitBreaker,
	l1 *gocache.Cache,
) *ResilientRedisRepo {
	return &ResilientRedisRepo{delegate: delegate, cb: cb, l1: l1}
}

func deviceTokenL1Key(kratosID, deviceID string) string {
	return fmt.Sprintf("drt:%s:%s", kratosID, deviceID)
}

// GetDeviceRefreshToken reads the stored Hydra refresh token for a device.
// L1 is consulted before Redis; on hit the Redis call is skipped entirely.
func (r *ResilientRedisRepo) GetDeviceRefreshToken(ctx context.Context, kratosID, deviceID string) (string, error) {
	key := deviceTokenL1Key(kratosID, deviceID)
	if val, found := r.l1.Get(key); found {
		L1CacheHits.WithLabelValues("device").Inc()
		return val.(string), nil
	}
	L1CacheMisses.WithLabelValues("device").Inc()

	if !r.cb.Allow() {
		return "", ErrRedisUnavailable
	}

	token, err := r.delegate.GetDeviceRefreshToken(ctx, kratosID, deviceID)
	if err != nil {
		if IsInfraError(err) {
			r.cb.RecordFailure()
			return "", ErrRedisUnavailable
		}
		r.cb.RecordSuccess()
		return "", err
	}
	r.cb.RecordSuccess()
	r.l1.Set(key, token, gocache.DefaultExpiration)
	return token, nil
}

// SaveLogin atomically enforces the 5-device limit and stores the refresh token.
// Returns ErrRedisUnavailable when the circuit is OPEN — login fails during outages.
// This is intentional: the Lua-script atomicity cannot be replicated without Redis.
func (r *ResilientRedisRepo) SaveLogin(ctx context.Context, kratosID, deviceID, hydraRefreshToken string, ttl time.Duration) error {
	if !r.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := r.delegate.SaveLogin(ctx, kratosID, deviceID, hydraRefreshToken, ttl); err != nil {
		if IsInfraError(err) {
			r.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		r.cb.RecordSuccess()
		return err
	}
	r.cb.RecordSuccess()
	r.l1.Set(deviceTokenL1Key(kratosID, deviceID), hydraRefreshToken, gocache.DefaultExpiration)
	return nil
}

// RotateRefreshToken replaces the stored refresh token for a device.
func (r *ResilientRedisRepo) RotateRefreshToken(ctx context.Context, kratosID, deviceID, newToken string, ttl time.Duration) error {
	if !r.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := r.delegate.RotateRefreshToken(ctx, kratosID, deviceID, newToken, ttl); err != nil {
		if IsInfraError(err) {
			r.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		r.cb.RecordSuccess()
		return err
	}
	r.cb.RecordSuccess()
	// Update L1 so the next GetDeviceRefreshToken returns the rotated token.
	r.l1.Set(deviceTokenL1Key(kratosID, deviceID), newToken, gocache.DefaultExpiration)
	return nil
}

// LogoutDevice removes the device's refresh token and device-set entry.
func (r *ResilientRedisRepo) LogoutDevice(ctx context.Context, kratosID, deviceID string) error {
	if !r.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := r.delegate.LogoutDevice(ctx, kratosID, deviceID); err != nil {
		if IsInfraError(err) {
			r.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		r.cb.RecordSuccess()
		return err
	}
	r.cb.RecordSuccess()
	r.l1.Delete(deviceTokenL1Key(kratosID, deviceID))
	return nil
}

// LogoutAll removes all device entries for a user.
func (r *ResilientRedisRepo) LogoutAll(ctx context.Context, kratosID string) error {
	if !r.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := r.delegate.LogoutAll(ctx, kratosID); err != nil {
		if IsInfraError(err) {
			r.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		r.cb.RecordSuccess()
		return err
	}
	r.cb.RecordSuccess()
	return nil
}

// compile-time interface check
var _ repository.RedisRepo = (*ResilientRedisRepo)(nil)
