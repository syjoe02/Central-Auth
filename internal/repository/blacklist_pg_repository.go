package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BlacklistPgRepository is the PostgreSQL fallback for the session blacklist.
// It is consulted only when the Redis circuit breaker is OPEN and the L1 cache misses.
// Redis remains the primary source of truth; this table provides durability during outages.
type BlacklistPgRepository interface {
	// IsBlacklisted returns true when session_id exists and expires_at > NOW().
	IsBlacklisted(ctx context.Context, sessionID string) (bool, error)
	// Add upserts a blacklist row. When the circuit is OPEN, Add is called directly
	// so that newly revoked sessions are persisted even without Redis.
	// UPSERT uses GREATEST to avoid shortening an existing expiry.
	Add(ctx context.Context, sessionID string, expiresAt time.Time) error
	// DeleteExpired removes rows whose expires_at <= NOW(). Optional maintenance.
	DeleteExpired(ctx context.Context) error
}

// PostgresBlacklistRepository implements BlacklistPgRepository using pgx.
type PostgresBlacklistRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresBlacklistRepository creates a repository backed by the given pool.
func NewPostgresBlacklistRepository(pool *pgxpool.Pool) *PostgresBlacklistRepository {
	return &PostgresBlacklistRepository{pool: pool}
}

// IsBlacklisted checks whether a non-expired row exists for sessionID.
func (r *PostgresBlacklistRepository) IsBlacklisted(ctx context.Context, sessionID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM blacklisted_sessions
			WHERE session_id = $1 AND expires_at > NOW()
		)`, sessionID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("blacklist pg: is_blacklisted %q: %w", sessionID, err)
	}
	return exists, nil
}

// Add upserts a blacklist row, never shortening an existing expiry.
func (r *PostgresBlacklistRepository) Add(ctx context.Context, sessionID string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	_, err := r.pool.Exec(ctx,
		`INSERT INTO blacklisted_sessions (session_id, expires_at)
		 VALUES ($1, $2)
		 ON CONFLICT (session_id) DO UPDATE
		   SET expires_at = GREATEST(EXCLUDED.expires_at, blacklisted_sessions.expires_at)`,
		sessionID, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("blacklist pg: add %q: %w", sessionID, err)
	}
	return nil
}

// DeleteExpired removes rows whose expiry has passed. Intended for periodic maintenance.
func (r *PostgresBlacklistRepository) DeleteExpired(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	_, err := r.pool.Exec(ctx,
		`DELETE FROM blacklisted_sessions WHERE expires_at <= NOW()`,
	)
	if err != nil {
		return fmt.Errorf("blacklist pg: delete_expired: %w", err)
	}
	return nil
}

// compile-time interface check
var _ BlacklistPgRepository = (*PostgresBlacklistRepository)(nil)

// pgx.ErrNoRows import guard (used by callers that check for not-found).
var _ = pgx.ErrNoRows
