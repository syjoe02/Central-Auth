package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNotFound is returned when a session does not exist or has expired.
var ErrNotFound = errors.New("session not found")

// Store defines the interface for BFF session persistence.
// Two Redis key patterns are used:
//   - bff:session:{sessionID}           → JSON-encoded BFFSession, TTL = ExpiresAt
//   - bff:user_sessions:{kratosID}      → Redis SET of active sessionIDs (for LogoutAll)
//   - bff:refresh_lock:{sessionID}      → SETNX lock for concurrent token refresh prevention
type Store interface {
	Create(ctx context.Context, s BFFSession) error
	Get(ctx context.Context, sessionID string) (BFFSession, error)
	Update(ctx context.Context, s BFFSession) error
	Delete(ctx context.Context, sessionID string) error
	GetAllForUser(ctx context.Context, kratosID string) ([]BFFSession, error)
	// DeleteAllForUser removes all sessions for the user and returns the deleted sessionIDs.
	DeleteAllForUser(ctx context.Context, kratosID string) ([]string, error)
	// AcquireRefreshLock tries to set a short-lived distributed lock to prevent
	// concurrent goroutines from refreshing the same session simultaneously.
	// Returns true if the lock was acquired by this caller.
	AcquireRefreshLock(ctx context.Context, sessionID string, ttl time.Duration) (bool, error)
	// ReleaseRefreshLock removes the refresh lock early (e.g., after refresh is done).
	ReleaseRefreshLock(ctx context.Context, sessionID string) error
}

// RedisStore implements Store using Redis.
type RedisStore struct {
	rdb        *redis.Client
	sessionTTL time.Duration
}

// NewRedisStore creates a RedisStore backed by the given client.
func NewRedisStore(rdb *redis.Client, sessionTTL time.Duration) *RedisStore {
	return &RedisStore{rdb: rdb, sessionTTL: sessionTTL}
}

func sessionKey(sessionID string) string    { return "bff:session:" + sessionID }
func userSessionsKey(kratosID string) string { return "bff:user_sessions:" + kratosID }
func refreshLockKey(sessionID string) string { return "bff:refresh_lock:" + sessionID }

// Create stores a new session and registers it in the per-user session index.
// Both operations are pipelined atomically.
func (rs *RedisStore) Create(ctx context.Context, s BFFSession) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("session store: marshal: %w", err)
	}

	ttl := time.Until(s.ExpiresAt)
	if ttl <= 0 {
		ttl = rs.sessionTTL
	}

	pipe := rs.rdb.TxPipeline()
	pipe.Set(ctx, sessionKey(s.SessionID), b, ttl)
	pipe.SAdd(ctx, userSessionsKey(s.KratosID), s.SessionID)
	// Keep the user index key alive as long as the longest session.
	pipe.Expire(ctx, userSessionsKey(s.KratosID), ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// Get retrieves a session by sessionID. Returns ErrNotFound if missing or expired.
func (rs *RedisStore) Get(ctx context.Context, sessionID string) (BFFSession, error) {
	val, err := rs.rdb.Get(ctx, sessionKey(sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return BFFSession{}, ErrNotFound
	}
	if err != nil {
		return BFFSession{}, fmt.Errorf("session store: get: %w", err)
	}

	var s BFFSession
	if err := json.Unmarshal([]byte(val), &s); err != nil {
		return BFFSession{}, fmt.Errorf("session store: unmarshal: %w", err)
	}
	return s, nil
}

// Update overwrites an existing session preserving its remaining TTL.
// Returns ErrNotFound if the session has already expired.
func (rs *RedisStore) Update(ctx context.Context, s BFFSession) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("session store: marshal update: %w", err)
	}
	ttl := time.Until(s.ExpiresAt)
	if ttl <= 0 {
		return ErrNotFound
	}
	return rs.rdb.Set(ctx, sessionKey(s.SessionID), b, ttl).Err()
}

// Delete removes a session and cleans up the per-user session index.
func (rs *RedisStore) Delete(ctx context.Context, sessionID string) error {
	s, err := rs.Get(ctx, sessionID)
	if errors.Is(err, ErrNotFound) {
		return nil // idempotent
	}
	if err != nil {
		return err
	}

	pipe := rs.rdb.TxPipeline()
	pipe.Del(ctx, sessionKey(sessionID))
	pipe.SRem(ctx, userSessionsKey(s.KratosID), sessionID)
	_, err = pipe.Exec(ctx)
	return err
}

// GetAllForUser returns all live sessions for the given kratosID.
// Stale index entries (sessions whose keys have expired) are silently skipped.
func (rs *RedisStore) GetAllForUser(ctx context.Context, kratosID string) ([]BFFSession, error) {
	sessionIDs, err := rs.rdb.SMembers(ctx, userSessionsKey(kratosID)).Result()
	if err != nil {
		return nil, fmt.Errorf("session store: list user sessions: %w", err)
	}

	var sessions []BFFSession
	for _, id := range sessionIDs {
		s, err := rs.Get(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue // expired; stale index entry
		}
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

// DeleteAllForUser deletes all sessions for a kratosID and removes the index.
// Returns the list of deleted sessionIDs so the caller can blacklist them.
func (rs *RedisStore) DeleteAllForUser(ctx context.Context, kratosID string) ([]string, error) {
	sessionIDs, err := rs.rdb.SMembers(ctx, userSessionsKey(kratosID)).Result()
	if err != nil {
		return nil, fmt.Errorf("session store: list user sessions: %w", err)
	}
	if len(sessionIDs) == 0 {
		return nil, nil
	}

	pipe := rs.rdb.TxPipeline()
	for _, id := range sessionIDs {
		pipe.Del(ctx, sessionKey(id))
	}
	pipe.Del(ctx, userSessionsKey(kratosID))
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("session store: delete all: %w", err)
	}
	return sessionIDs, nil
}

// AcquireRefreshLock uses SETNX to atomically claim a short-lived lock.
// Returns true if acquired. Callers that lose the race should re-read the
// session to get the tokens updated by the winning goroutine.
func (rs *RedisStore) AcquireRefreshLock(ctx context.Context, sessionID string, ttl time.Duration) (bool, error) {
	ok, err := rs.rdb.SetNX(ctx, refreshLockKey(sessionID), "1", ttl).Result()
	return ok, err
}

// ReleaseRefreshLock removes the distributed refresh lock before its TTL expires.
func (rs *RedisStore) ReleaseRefreshLock(ctx context.Context, sessionID string) error {
	return rs.rdb.Del(ctx, refreshLockKey(sessionID)).Err()
}

// compile-time interface check
var _ Store = (*RedisStore)(nil)
