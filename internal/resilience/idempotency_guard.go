package resilience

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// IdempotencyCache is the minimal interface the gRPC idempotency interceptor
// needs from Redis. Extracting it allows the resilient shim to be injected
// without exposing the full *redis.Client to the interceptor package.
type IdempotencyCache interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

// ResilientIdempotencyCache wraps *redis.Client with circuit-breaker awareness.
// When the circuit is OPEN both Get and Set behave as no-ops:
//   - Get returns a cmd carrying redis.Nil (cache miss) so the interceptor falls through.
//   - Set returns a no-error cmd so the interceptor does not log spurious errors.
// Idempotency is a best-effort optimisation; skipping it during a Redis outage
// is safe (callers retry from scratch rather than receiving stale replays).
type ResilientIdempotencyCache struct {
	rdb *redis.Client
	cb  CircuitBreaker
}

// NewResilientIdempotencyCache creates the shim.
func NewResilientIdempotencyCache(rdb *redis.Client, cb CircuitBreaker) *ResilientIdempotencyCache {
	return &ResilientIdempotencyCache{rdb: rdb, cb: cb}
}

// Get delegates to Redis when the circuit is CLOSED; returns a redis.Nil cmd when OPEN.
func (c *ResilientIdempotencyCache) Get(ctx context.Context, key string) *redis.StringCmd {
	if !c.cb.Allow() {
		cmd := redis.NewStringCmd(ctx)
		cmd.SetErr(redis.Nil)
		return cmd
	}
	result := c.rdb.Get(ctx, key)
	if err := result.Err(); err != nil && !errors.Is(err, redis.Nil) && IsInfraError(err) {
		c.cb.RecordFailure()
	} else {
		c.cb.RecordSuccess()
	}
	return result
}

// Set delegates to Redis when the circuit is CLOSED; returns a no-op cmd when OPEN.
func (c *ResilientIdempotencyCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	if !c.cb.Allow() {
		cmd := redis.NewStatusCmd(ctx)
		// No error set — interceptor checks err and skips caching silently.
		return cmd
	}
	result := c.rdb.Set(ctx, key, value, expiration)
	if err := result.Err(); err != nil && IsInfraError(err) {
		c.cb.RecordFailure()
	} else {
		c.cb.RecordSuccess()
	}
	return result
}

// compile-time interface check
var _ IdempotencyCache = (*ResilientIdempotencyCache)(nil)
