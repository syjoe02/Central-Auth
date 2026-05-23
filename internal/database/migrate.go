// Package database provides the RunMigrations helper that applies pending
// golang-migrate SQL migrations at service startup. Migrations are embedded
// into the binary via //go:embed so no filesystem path is required at runtime.
package database

import (
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // registers "pgx5" scheme
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// RunMigrations applies all pending up-migrations against the given DSN.
// It is safe to call on a database that is already at the latest version
// (migrate.ErrNoChange is treated as success).
func RunMigrations(dsn string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	// golang-migrate pgx/v5 driver registers under "pgx5", not "postgres".
	migrateDSN := strings.Replace(dsn, "postgres://", "pgx5://", 1)
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateDSN)
	if err != nil {
		// Do NOT wrap err directly: the pgx driver embeds the full DSN
		// (including the password) in its error string. Return a redacted
		// message so credentials never appear in log output.
		return fmt.Errorf("create migrator: connection failed (credentials redacted)")
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}
