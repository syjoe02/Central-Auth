package resilience

import (
	"context"
	"log/slog"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/session"
)

// logWithReqID is defined in resilient_blacklist.go (same package resilience).

const sessionL1Prefix = "sess:"

// copySess returns a value copy of sess.
// BFFSession is currently composed entirely of value types (string, time.Time),
// so a struct copy is safe. This helper makes the defensive-copy contract
// explicit: if pointer or slice fields are ever added to BFFSession, this
// function must be updated to perform a deep copy.
func copySess(sess session.BFFSession) session.BFFSession {
	return sess
}

// ResilientSessionStore wraps session.Store with circuit-breaker protection
// and an L1 in-process cache for read operations.
//
// Fallback hierarchy when the circuit is OPEN:
//   Get:                  L1 cache → ErrNotFound (forces re-authentication).
//   Create / Update:      Updates L1, returns ErrRedisUnavailable to caller.
//   Delete:               Always evicts L1 first; returns ErrRedisUnavailable when OPEN.
//   AcquireRefreshLock:   Returns (false, nil) — permits concurrent refresh;
//                         acceptable degraded behaviour vs. denying all token refreshes.
//   All other writes:     Return ErrRedisUnavailable when OPEN.
type ResilientSessionStore struct {
	delegate session.Store
	cb       CircuitBreaker
	l1       *gocache.Cache
}

// NewResilientSessionStore creates the decorator.
func NewResilientSessionStore(
	delegate session.Store,
	cb CircuitBreaker,
	l1 *gocache.Cache,
) *ResilientSessionStore {
	return &ResilientSessionStore{delegate: delegate, cb: cb, l1: l1}
}

// Get retrieves a BFF session.
// L1 is consulted first; on miss the delegate is called and L1 is populated.
func (s *ResilientSessionStore) Get(ctx context.Context, sessionID string) (session.BFFSession, error) {
	key := sessionL1Prefix + sessionID
	if val, found := s.l1.Get(key); found {
		L1CacheHits.WithLabelValues("session").Inc()
		return copySess(val.(session.BFFSession)), nil
	}
	L1CacheMisses.WithLabelValues("session").Inc()

	if !s.cb.Allow() {
		return session.BFFSession{}, session.ErrNotFound
	}

	sess, err := s.delegate.Get(ctx, sessionID)
	if err != nil {
		if IsInfraError(err) {
			s.cb.RecordFailure()
			logWithReqID(ctx, slog.LevelError, "session store: Redis infra error on Get", "session_id", sessionID, "error", err)
			return session.BFFSession{}, session.ErrNotFound
		}
		// Domain error (ErrNotFound, etc.) — not an infra failure.
		s.cb.RecordSuccess()
		return session.BFFSession{}, err
	}
	s.cb.RecordSuccess()
	s.l1.Set(key, sess, gocache.DefaultExpiration)
	return sess, nil
}

// Create writes a new session to Redis and mirrors it into L1.
func (s *ResilientSessionStore) Create(ctx context.Context, sess session.BFFSession) error {
	if !s.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := s.delegate.Create(ctx, sess); err != nil {
		if IsInfraError(err) {
			s.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		s.cb.RecordSuccess()
		return err
	}
	s.cb.RecordSuccess()
	s.l1.Set(sessionL1Prefix+sess.SessionID, sess, gocache.DefaultExpiration)
	return nil
}

// Update refreshes an existing session in Redis and updates L1.
func (s *ResilientSessionStore) Update(ctx context.Context, sess session.BFFSession) error {
	if !s.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := s.delegate.Update(ctx, sess); err != nil {
		if IsInfraError(err) {
			s.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		s.cb.RecordSuccess()
		return err
	}
	s.cb.RecordSuccess()
	s.l1.Set(sessionL1Prefix+sess.SessionID, sess, gocache.DefaultExpiration)
	return nil
}

// Delete removes a session from Redis and evicts it from L1.
// L1 eviction happens before the CB check so that a deleted session is never
// served from cache even when Redis is unavailable.
func (s *ResilientSessionStore) Delete(ctx context.Context, sessionID string) error {
	s.l1.Delete(sessionL1Prefix + sessionID) // always evict, even when OPEN
	if !s.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := s.delegate.Delete(ctx, sessionID); err != nil {
		if IsInfraError(err) {
			s.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		s.cb.RecordSuccess()
		return err
	}
	s.cb.RecordSuccess()
	return nil
}

// GetAllForUser retrieves all sessions for a user.
func (s *ResilientSessionStore) GetAllForUser(ctx context.Context, kratosID string) ([]session.BFFSession, error) {
	if !s.cb.Allow() {
		return nil, ErrRedisUnavailable
	}
	sessions, err := s.delegate.GetAllForUser(ctx, kratosID)
	if err != nil && IsInfraError(err) {
		s.cb.RecordFailure()
		return nil, ErrRedisUnavailable
	}
	s.cb.RecordSuccess()
	// Return copies to prevent callers from mutating cached data.
	out := make([]session.BFFSession, len(sessions))
	for i, sess := range sessions {
		out[i] = copySess(sess)
	}
	return out, err
}

// DeleteAllForUser removes all sessions for a user and returns the deleted IDs.
// Also evicts any L1 entries we know about (best-effort; we don't have a full index).
func (s *ResilientSessionStore) DeleteAllForUser(ctx context.Context, kratosID string) ([]string, error) {
	if !s.cb.Allow() {
		return nil, ErrRedisUnavailable
	}
	ids, err := s.delegate.DeleteAllForUser(ctx, kratosID)
	if err != nil && IsInfraError(err) {
		s.cb.RecordFailure()
		return nil, ErrRedisUnavailable
	}
	s.cb.RecordSuccess()
	// Evict all returned IDs from L1.
	for _, id := range ids {
		s.l1.Delete(sessionL1Prefix + id)
	}
	return ids, err
}

// AcquireRefreshLock attempts to acquire a distributed refresh lock.
// Returns (false, nil) when the circuit is OPEN — allows concurrent token refresh
// as a safe degraded behaviour (vs. denying all refreshes during an outage).
func (s *ResilientSessionStore) AcquireRefreshLock(ctx context.Context, sessionID string, ttl time.Duration) (bool, error) {
	if !s.cb.Allow() {
		return false, nil
	}
	acquired, err := s.delegate.AcquireRefreshLock(ctx, sessionID, ttl)
	if err != nil && IsInfraError(err) {
		s.cb.RecordFailure()
		return false, nil
	}
	s.cb.RecordSuccess()
	return acquired, err
}

// ReleaseRefreshLock removes the refresh lock.
func (s *ResilientSessionStore) ReleaseRefreshLock(ctx context.Context, sessionID string) error {
	if !s.cb.Allow() {
		return ErrRedisUnavailable
	}
	if err := s.delegate.ReleaseRefreshLock(ctx, sessionID); err != nil {
		if IsInfraError(err) {
			s.cb.RecordFailure()
			return ErrRedisUnavailable
		}
		s.cb.RecordSuccess()
		return err
	}
	s.cb.RecordSuccess()
	return nil
}

// compile-time interface check
var _ session.Store = (*ResilientSessionStore)(nil)
