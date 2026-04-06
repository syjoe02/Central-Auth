package resilience

import (
	"context"
	"fmt"
	"log"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/blacklist"
	"central-auth/internal/repository"
	"central-auth/internal/requestid"
)

// logWithReqID prefixes the request ID from ctx (if any) to the log line.
func logWithReqID(ctx context.Context, format string, args ...any) {
	if rid := requestid.FromContext(ctx); rid != "" {
		format = "[" + rid + "] " + format
	}
	log.Printf(format, args...)
}

// ResilientBlacklist wraps blacklist.Blacklist with circuit-breaker protection,
// L1 in-process cache, and a PostgreSQL fallback.
//
// Fallback hierarchy when the circuit is OPEN:
//   IsBlacklisted: L1 cache → PostgreSQL blacklisted_sessions → update L1.
//                  FAIL-CLOSED: any error at the PG layer returns (true, err).
//   Add:           PostgreSQL write + L1 write; returns ErrRedisUnavailable so
//                  callers can log the degraded write without aborting security-
//                  critical operations (e.g. logout still clears the browser cookie).
//   AddBatch:      Same as Add, iterated per session ID.
type ResilientBlacklist struct {
	delegate blacklist.Blacklist
	cb       CircuitBreaker
	l1       *gocache.Cache
	pgRepo   repository.BlacklistPgRepository
}

// NewResilientBlacklist creates the decorator.
func NewResilientBlacklist(
	delegate blacklist.Blacklist,
	cb CircuitBreaker,
	l1 *gocache.Cache,
	pgRepo repository.BlacklistPgRepository,
) *ResilientBlacklist {
	return &ResilientBlacklist{delegate: delegate, cb: cb, l1: l1, pgRepo: pgRepo}
}

// IsBlacklisted checks whether sessionID has been revoked.
// FAIL-CLOSED: any error (at any layer) returns (true, err) to deny access.
func (r *ResilientBlacklist) IsBlacklisted(ctx context.Context, sessionID string) (bool, error) {
	if r.cb.Allow() {
		result, err := r.delegate.IsBlacklisted(ctx, sessionID)
		if err != nil && IsInfraError(err) {
			r.cb.RecordFailure()
			// Infra failure — fall through to L1/PG path.
		} else {
			r.cb.RecordSuccess()
			// Mirror to L1 so the next probe-period request is served from cache.
			r.l1.Set(sessionID, result, gocache.DefaultExpiration)
			return result, err
		}
	}

	// Circuit is OPEN (or we just had an infra failure on the CLOSED path).
	if val, found := r.l1.Get(sessionID); found {
		L1CacheHits.WithLabelValues("blacklist").Inc()
		return val.(bool), nil
	}
	L1CacheMisses.WithLabelValues("blacklist").Inc()

	result, err := r.pgRepo.IsBlacklisted(ctx, sessionID)
	if err != nil {
		// FAIL-CLOSED: PG error → deny access.
		logWithReqID(ctx, "[ERROR] blacklist: pg fallback is_blacklisted failed (fail-closed): %v", err)
		return true, fmt.Errorf("blacklist: pg fallback is_blacklisted: %w", err)
	}
	PgFallbackTotal.WithLabelValues("is_blacklisted").Inc()
	logWithReqID(ctx, "[INFO] blacklist: pg fallback is_blacklisted hit sessionID=%s result=%v", sessionID, result)
	r.l1.Set(sessionID, result, gocache.DefaultExpiration)
	return result, nil
}

// Add blacklists sessionID for ttl.
// When the circuit is OPEN it writes to PostgreSQL + L1 and returns ErrRedisUnavailable.
// Callers must treat ErrRedisUnavailable as a warning, not a fatal error, so that
// logout can still clear the browser cookie even during a Redis outage.
func (r *ResilientBlacklist) Add(ctx context.Context, sessionID string, ttl time.Duration) error {
	if r.cb.Allow() {
		err := r.delegate.Add(ctx, sessionID, ttl)
		if err != nil && IsInfraError(err) {
			r.cb.RecordFailure()
			// Infra failure — fall through to dual-write path.
		} else {
			r.cb.RecordSuccess()
			if err == nil {
				r.l1.Set(sessionID, true, ttl)
			}
			return err
		}
	}

	// OPEN path: dual-write to PG + L1.
	expiresAt := time.Now().Add(ttl)
	if pgErr := r.pgRepo.Add(ctx, sessionID, expiresAt); pgErr != nil {
		logWithReqID(ctx, "[ERROR] blacklist: pg fallback add failed sessionID=%s: %v", sessionID, pgErr)
		return fmt.Errorf("blacklist: pg fallback add: %w", pgErr)
	}
	PgFallbackTotal.WithLabelValues("add").Inc()
	logWithReqID(ctx, "[WARN] blacklist: Redis unavailable, wrote sessionID=%s to PG+L1 fallback", sessionID)
	r.l1.Set(sessionID, true, ttl)
	return ErrRedisUnavailable
}

// AddBatch blacklists multiple sessions. Falls back to per-session PG writes when OPEN.
func (r *ResilientBlacklist) AddBatch(ctx context.Context, sessionIDs []string, ttl time.Duration) error {
	if len(sessionIDs) == 0 {
		return nil
	}

	if r.cb.Allow() {
		err := r.delegate.AddBatch(ctx, sessionIDs, ttl)
		if err != nil && IsInfraError(err) {
			r.cb.RecordFailure()
			// Fall through to per-session PG writes.
		} else {
			r.cb.RecordSuccess()
			if err == nil {
				for _, id := range sessionIDs {
					r.l1.Set(id, true, ttl)
				}
			}
			return err
		}
	}

	// OPEN path: write each session to PG + L1.
	expiresAt := time.Now().Add(ttl)
	for _, id := range sessionIDs {
		if pgErr := r.pgRepo.Add(ctx, id, expiresAt); pgErr != nil {
			return fmt.Errorf("blacklist: pg fallback add_batch: %w", pgErr)
		}
		r.l1.Set(id, true, ttl)
	}
	PgFallbackTotal.WithLabelValues("add_batch").Inc()
	return ErrRedisUnavailable
}

// compile-time interface check
var _ blacklist.Blacklist = (*ResilientBlacklist)(nil)
