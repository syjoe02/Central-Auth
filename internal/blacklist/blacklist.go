// Package blacklist provides immediate session invalidation via a Redis-backed
// revocation list. Entries self-expire using Redis TTL so no background sweep
// is needed. The implementation is fail-closed: Redis errors are treated as
// blacklisted to prevent access with potentially revoked sessions.
package blacklist

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// minBlacklistTTL is the minimum blacklist entry lifetime written even when the
// session's ExpiresAt is in the past (clock skew / eventual consistency guard).
// This ensures in-flight requests that already passed the blacklist check and
// are mid-flight cannot reuse a session that Redis hasn't yet evicted.
const minBlacklistTTL = 60 * time.Second

// Blacklist defines the interface for session revocation.
type Blacklist interface {
	// Add blacklists a sessionID for the given TTL. Fail-closed: callers must
	// abort logout if this returns an error.
	Add(ctx context.Context, sessionID string, ttl time.Duration) error
	// IsBlacklisted returns true if the session has been revoked.
	// Fail-closed: a Redis error is treated as blacklisted.
	IsBlacklisted(ctx context.Context, sessionID string) (bool, error)
	// AddBatch blacklists multiple sessions in a single pipeline.
	AddBatch(ctx context.Context, sessionIDs []string, ttl time.Duration) error
}

// RedisBlacklist implements Blacklist using Redis SET keys with expiry.
// Key pattern: bff:blacklist:{sessionID} → "1" with TTL = remaining session lifetime.
type RedisBlacklist struct {
	rdb *redis.Client
}

// NewRedisBlacklist creates a RedisBlacklist backed by the given client.
func NewRedisBlacklist(rdb *redis.Client) *RedisBlacklist {
	return &RedisBlacklist{rdb: rdb}
}

func blacklistKey(sessionID string) string {
	return "bff:blacklist:" + sessionID
}

// Add writes a blacklist entry with a TTL equal to the remaining session lifetime.
// If ttl <= 0 the session has already expired but we still write a minimum
// TTL entry to guard against in-flight requests that passed the check before
// the session expired (clock skew / eventual Redis eviction lag).
func (b *RedisBlacklist) Add(ctx context.Context, sessionID string, ttl time.Duration) error {
	if ttl <= 0 {
		log.Printf("[WARN] blacklist: Add called with non-positive TTL (%v) for session %q — writing minimum TTL %v",
			ttl, sessionID, minBlacklistTTL)
		ttl = minBlacklistTTL
	}
	if err := b.rdb.Set(ctx, blacklistKey(sessionID), "1", ttl).Err(); err != nil {
		return fmt.Errorf("blacklist: add %q: %w", sessionID, err)
	}
	return nil
}

// IsBlacklisted returns true if the sessionID is present in the blacklist.
// Fail-closed: Redis errors return (true, err) to prevent access.
func (b *RedisBlacklist) IsBlacklisted(ctx context.Context, sessionID string) (bool, error) {
	n, err := b.rdb.Exists(ctx, blacklistKey(sessionID)).Result()
	if err != nil {
		return true, fmt.Errorf("blacklist: check %q: %w", sessionID, err)
	}
	return n > 0, nil
}

// AddBatch blacklists multiple sessionIDs in a single Redis pipeline.
func (b *RedisBlacklist) AddBatch(ctx context.Context, sessionIDs []string, ttl time.Duration) error {
	if len(sessionIDs) == 0 || ttl <= 0 {
		return nil
	}
	pipe := b.rdb.Pipeline()
	for _, id := range sessionIDs {
		pipe.Set(ctx, blacklistKey(id), "1", ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("blacklist: batch add: %w", err)
	}
	return nil
}

// compile-time interface check
var _ Blacklist = (*RedisBlacklist)(nil)
