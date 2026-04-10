package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BlacklistTargetType represents the kind of entity being blocked globally.
type BlacklistTargetType string

const (
	TargetTypeUser       BlacklistTargetType = "USER"
	TargetTypeJTI        BlacklistTargetType = "JTI"
	TargetTypeServiceKey BlacklistTargetType = "SERVICE_KEY"
)

// GlobalBlacklistEntry is one row from the blacklists table.
type GlobalBlacklistEntry struct {
	TargetType  BlacklistTargetType
	TargetValue string
	Reason      string
	CreatedAt   time.Time
}

// GlobalBlacklistRepository manages the admin-driven blacklists table.
// Unlike blacklisted_sessions (BFF session revocation by JTI), this table
// stores durable identity-level blocks that fan-out to all Django instances
// via the blacklist-sync Kafka topic.
type GlobalBlacklistRepository interface {
	// Add upserts a global block entry.
	Add(ctx context.Context, targetType BlacklistTargetType, targetValue, reason string) error
	// IsBlacklisted returns true when the entry exists in the blacklists table.
	IsBlacklisted(ctx context.Context, targetType BlacklistTargetType, targetValue string) (bool, error)
	// ListAll returns all entries for bulk L1 warm-up on service start.
	ListAll(ctx context.Context) ([]GlobalBlacklistEntry, error)
	// Remove deletes a global block entry (unblock).
	Remove(ctx context.Context, targetType BlacklistTargetType, targetValue string) error
}

// PostgresGlobalBlacklistRepository implements GlobalBlacklistRepository using pgx.
type PostgresGlobalBlacklistRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresGlobalBlacklistRepository creates a repository backed by the given pool.
func NewPostgresGlobalBlacklistRepository(pool *pgxpool.Pool) *PostgresGlobalBlacklistRepository {
	return &PostgresGlobalBlacklistRepository{pool: pool}
}

// Add upserts a global block, updating the reason if the entry already exists.
func (r *PostgresGlobalBlacklistRepository) Add(ctx context.Context, targetType BlacklistTargetType, targetValue, reason string) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	_, err := r.pool.Exec(ctx,
		`INSERT INTO blacklists (target_type, target_value, reason)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (target_type, target_value) DO UPDATE SET reason = EXCLUDED.reason`,
		string(targetType), targetValue, reason,
	)
	if err != nil {
		return fmt.Errorf("global blacklist: add %s/%q: %w", targetType, targetValue, err)
	}
	return nil
}

// IsBlacklisted returns true when the entry exists in the blacklists table.
func (r *PostgresGlobalBlacklistRepository) IsBlacklisted(ctx context.Context, targetType BlacklistTargetType, targetValue string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM blacklists WHERE target_type = $1 AND target_value = $2)`,
		string(targetType), targetValue,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("global blacklist: is_blacklisted %s/%q: %w", targetType, targetValue, err)
	}
	return exists, nil
}

// ListAll returns all entries ordered by creation time.
// Used on service start to warm up Django L1 caches via Kafka replay.
func (r *PostgresGlobalBlacklistRepository) ListAll(ctx context.Context) ([]GlobalBlacklistEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	rows, err := r.pool.Query(ctx,
		`SELECT target_type, target_value, COALESCE(reason, ''), created_at
		 FROM blacklists
		 ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("global blacklist: list_all: %w", err)
	}
	defer rows.Close()

	var entries []GlobalBlacklistEntry
	for rows.Next() {
		var e GlobalBlacklistEntry
		var tt string
		if err := rows.Scan(&tt, &e.TargetValue, &e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("global blacklist: list_all scan: %w", err)
		}
		e.TargetType = BlacklistTargetType(tt)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Remove deletes a global block entry (unblock operation).
func (r *PostgresGlobalBlacklistRepository) Remove(ctx context.Context, targetType BlacklistTargetType, targetValue string) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	_, err := r.pool.Exec(ctx,
		`DELETE FROM blacklists WHERE target_type = $1 AND target_value = $2`,
		string(targetType), targetValue,
	)
	if err != nil {
		return fmt.Errorf("global blacklist: remove %s/%q: %w", targetType, targetValue, err)
	}
	return nil
}

// compile-time interface check
var _ GlobalBlacklistRepository = (*PostgresGlobalBlacklistRepository)(nil)
