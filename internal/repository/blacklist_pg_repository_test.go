//go:build integration

package repository_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"central-auth/internal/repository"
)

// TestBlacklistPg_* are integration tests that require a real PostgreSQL instance.
// They are automatically skipped when TEST_DB_URL is not set.
func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set; skipping PG integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	// Ensure the table exists (migration must have run before tests).
	if _, err := pool.Exec(context.Background(),
		`CREATE TABLE IF NOT EXISTS blacklisted_sessions (
			session_id TEXT PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL
		)`); err != nil {
		t.Fatalf("ensure table: %v", err)
	}
	// Clean slate for each test run.
	if _, err := pool.Exec(context.Background(),
		`TRUNCATE blacklisted_sessions`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func TestBlacklistPg_AddAndIsBlacklisted_RoundTrip(t *testing.T) {
	pool := openTestPool(t)
	repo := repository.NewPostgresBlacklistRepository(pool)
	ctx := context.Background()

	exp := time.Now().Add(5 * time.Minute)
	if err := repo.Add(ctx, "sess-roundtrip", exp); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := repo.IsBlacklisted(ctx, "sess-roundtrip")
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if !got {
		t.Fatal("expected session to be blacklisted after Add")
	}
}

func TestBlacklistPg_ExpiredEntry_ReturnsFalse(t *testing.T) {
	pool := openTestPool(t)
	repo := repository.NewPostgresBlacklistRepository(pool)
	ctx := context.Background()

	// Insert a row that expired in the past.
	past := time.Now().Add(-1 * time.Minute)
	if err := repo.Add(ctx, "sess-expired", past); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := repo.IsBlacklisted(ctx, "sess-expired")
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if got {
		t.Fatal("expected false for an expired blacklist entry")
	}
}

func TestBlacklistPg_Upsert_ExtendsExpiry(t *testing.T) {
	pool := openTestPool(t)
	repo := repository.NewPostgresBlacklistRepository(pool)
	ctx := context.Background()

	short := time.Now().Add(1 * time.Minute)
	long := time.Now().Add(10 * time.Minute)

	if err := repo.Add(ctx, "sess-upsert", short); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	// Second Add with a longer expiry should win via GREATEST.
	if err := repo.Add(ctx, "sess-upsert", long); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	var storedExp time.Time
	err := pool.QueryRow(ctx,
		`SELECT expires_at FROM blacklisted_sessions WHERE session_id = 'sess-upsert'`,
	).Scan(&storedExp)
	if err != nil {
		t.Fatalf("read expiry: %v", err)
	}
	// Allow 1-second tolerance for clock drift between writes.
	if storedExp.Before(long.Add(-1 * time.Second)) {
		t.Fatalf("expected expiry >= %v, got %v", long, storedExp)
	}
}

func TestBlacklistPg_DeleteExpired_RemovesOldRows(t *testing.T) {
	pool := openTestPool(t)
	repo := repository.NewPostgresBlacklistRepository(pool)
	ctx := context.Background()

	past := time.Now().Add(-1 * time.Minute)
	future := time.Now().Add(5 * time.Minute)
	if err := repo.Add(ctx, "sess-del-old", past); err != nil {
		t.Fatalf("Add old: %v", err)
	}
	if err := repo.Add(ctx, "sess-del-new", future); err != nil {
		t.Fatalf("Add new: %v", err)
	}
	if err := repo.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	old, _ := repo.IsBlacklisted(ctx, "sess-del-old")
	fresh, _ := repo.IsBlacklisted(ctx, "sess-del-new")
	if old {
		t.Fatal("expected expired row to be deleted")
	}
	if !fresh {
		t.Fatal("expected non-expired row to survive DeleteExpired")
	}
}
