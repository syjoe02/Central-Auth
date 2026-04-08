package resilience

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/blacklist"
	"central-auth/internal/repository"
	"central-auth/internal/requestid"
)

// logWriter delegates to the standard log.Writer() so that tests can redirect
// output via log.SetOutput and capture structured slog lines in a buffer.
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) { return log.Writer().Write(p) }

// resilienceLogger emits structured JSON for Loki ingestion.
// Writing through logWriter (not os.Stdout directly) allows tests to redirect
// log output via log.SetOutput without re-initialising the slog handler.
var resilienceLogger = slog.New(slog.NewJSONHandler(logWriter{}, nil)).With(slog.String("service", "central-auth"))

// logWithReqID emits a structured JSON log line, adding "request_id" from ctx when present.
func logWithReqID(ctx context.Context, level slog.Level, msg string, args ...any) {
	if rid := requestid.FromContext(ctx); rid != "" {
		args = append([]any{slog.String("request_id", rid)}, args...)
	}
	resilienceLogger.Log(ctx, level, msg, args...)
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
		logWithReqID(ctx, slog.LevelError, "blacklist: pg fallback is_blacklisted failed (fail-closed)", "error", err)
		return true, fmt.Errorf("blacklist: pg fallback is_blacklisted: %w", err)
	}
	PgFallbackTotal.WithLabelValues("is_blacklisted").Inc()
	logWithReqID(ctx, slog.LevelInfo, "blacklist: pg fallback is_blacklisted hit", "session_id", sessionID, "result", result)
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
		logWithReqID(ctx, slog.LevelError, "blacklist: pg fallback add failed", "session_id", sessionID, "error", pgErr)
		return fmt.Errorf("blacklist: pg fallback add: %w", pgErr)
	}
	PgFallbackTotal.WithLabelValues("add").Inc()
	logWithReqID(ctx, slog.LevelWarn, "blacklist: Redis unavailable, wrote to PG+L1 fallback", "session_id", sessionID)
	r.l1.Set(sessionID, true, ttl)
	return ErrRedisUnavailable
}

// StartBackgroundSync launches a goroutine that re-syncs all active blacklisted
// JTIs from PostgreSQL into the L1 cache every syncInterval (typically 1 minute).
// The sync only runs while the circuit is OPEN, where per-request PG lookups would
// otherwise cause a query spike on every IsBlacklisted call.
//
// The goroutine exits cleanly when ctx is cancelled (e.g. on graceful shutdown).
// Call once from main after constructing the ResilientBlacklist.
func (r *ResilientBlacklist) StartBackgroundSync(ctx context.Context, syncInterval time.Duration) {
	go func() {
		defer func() {
			if p := recover(); p != nil {
				resilienceLogger.LogAttrs(ctx, slog.LevelError,
					"blacklist: bg sync goroutine recovered from panic",
					slog.Any("panic", p),
				)
			}
		}()
		ticker := time.NewTicker(syncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if r.cb.State() == StateOpen {
					r.syncFromPG(ctx)
				}
			}
		}
	}()
}

// syncFromPG fetches all non-expired blacklist rows from PostgreSQL and stores
// them in the L1 cache. Each entry gets a TTL matching its remaining lifetime.
func (r *ResilientBlacklist) syncFromPG(ctx context.Context) {
	entries, err := r.pgRepo.ListActive(ctx)
	if err != nil {
		resilienceLogger.LogAttrs(ctx, slog.LevelError,
			"blacklist: bg sync list_active failed",
			slog.String("error", err.Error()),
		)
		return
	}
	now := time.Now()
	loaded := 0
	for _, e := range entries {
		ttl := e.ExpiresAt.Sub(now)
		if ttl <= 0 {
			continue // race: expired between query and now — skip
		}
		r.l1.Set(e.SessionID, true, ttl)
		loaded++
	}
	resilienceLogger.LogAttrs(ctx, slog.LevelInfo,
		"blacklist: bg sync completed",
		slog.Int("loaded", loaded),
		slog.String("circuit_state", "OPEN"),
	)
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
