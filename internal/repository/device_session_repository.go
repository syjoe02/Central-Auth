package repository

import (
	"context"
	"time"

	"central-auth/internal/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

const dbQueryTimeout = 3 * time.Second

// DeviceSessionRepository defines the application-level device session operations.
// It reads and writes the device_sessions table only — never the Kratos or Hydra databases.
type DeviceSessionRepository interface {
	SaveDeviceSession(ctx context.Context, session *domain.DeviceSession) error
	UpdateLastUsedAt(ctx context.Context, kratosID, deviceID string) error
	RevokeDevice(ctx context.Context, kratosID, deviceID string) error
	RevokeAllDevices(ctx context.Context, kratosID string) error
	GetDeviceSessions(ctx context.Context, kratosID string) ([]domain.DeviceSession, error)
	CountActiveDevices(ctx context.Context, kratosID string) (int, error)
}

// PostgresDeviceSessionRepository implements DeviceSessionRepository using pgx.
type PostgresDeviceSessionRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresDeviceSessionRepository creates a new repository backed by the given pool.
func NewPostgresDeviceSessionRepository(pool *pgxpool.Pool) *PostgresDeviceSessionRepository {
	return &PostgresDeviceSessionRepository{pool: pool}
}

// SaveDeviceSession upserts a device session row.
//
// On conflict (kratos_id, device_id) the following rules apply:
//
//   - hydra_jti: updated only when the new value is non-NULL; a NULL incoming
//     JTI (ValidateAccessToken failed) never overwrites a previously stored JTI.
//   - last_used_at: preserved if the existing value is more recent (GREATEST),
//     preventing a Kafka replay from wiping activity written by UpdateLastUsedAt.
//   - revoked: preserved if the session was previously revoked AND the new login
//     brings a different JTI (genuine re-login un-revokes); otherwise kept as-is.
//     This prevents a replayed Kafka message from silently un-revoking a device.
//   - user_agent / ip_address: always updated to reflect the current login context.
func (r *PostgresDeviceSessionRepository) SaveDeviceSession(ctx context.Context, s *domain.DeviceSession) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	_, err := r.pool.Exec(ctx, `
		INSERT INTO device_sessions
			(kratos_id, device_id, hydra_jti, issued_at, last_used_at, revoked, user_agent, ip_address)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (kratos_id, device_id) DO UPDATE SET
			hydra_jti    = COALESCE(EXCLUDED.hydra_jti, device_sessions.hydra_jti),
			issued_at    = EXCLUDED.issued_at,
			last_used_at = COALESCE(GREATEST(EXCLUDED.last_used_at, device_sessions.last_used_at),
			                        device_sessions.last_used_at,
			                        EXCLUDED.last_used_at),
			revoked      = CASE
			                   WHEN EXCLUDED.hydra_jti IS NOT NULL
			                        AND EXCLUDED.hydra_jti IS DISTINCT FROM device_sessions.hydra_jti
			                   THEN false
			                   ELSE device_sessions.revoked
			               END,
			user_agent   = EXCLUDED.user_agent,
			ip_address   = EXCLUDED.ip_address
	`,
		s.KratosID, s.DeviceID, s.HydraJTI,
		s.IssuedAt, s.LastUsedAt, s.Revoked,
		s.UserAgent, s.IP,
	)
	return err
}

// UpdateLastUsedAt sets last_used_at to NOW() for the given device.
func (r *PostgresDeviceSessionRepository) UpdateLastUsedAt(ctx context.Context, kratosID, deviceID string) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	_, err := r.pool.Exec(ctx, `
		UPDATE device_sessions
		SET    last_used_at = NOW()
		WHERE  kratos_id = $1 AND device_id = $2
	`, kratosID, deviceID)
	return err
}

// RevokeDevice marks a single device session as revoked.
func (r *PostgresDeviceSessionRepository) RevokeDevice(ctx context.Context, kratosID, deviceID string) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	_, err := r.pool.Exec(ctx, `
		UPDATE device_sessions
		SET    revoked = true
		WHERE  kratos_id = $1 AND device_id = $2
	`, kratosID, deviceID)
	return err
}

// RevokeAllDevices marks all device sessions for the given Kratos identity as revoked.
func (r *PostgresDeviceSessionRepository) RevokeAllDevices(ctx context.Context, kratosID string) error {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	_, err := r.pool.Exec(ctx, `
		UPDATE device_sessions
		SET    revoked = true
		WHERE  kratos_id = $1
	`, kratosID)
	return err
}

// GetDeviceSessions returns all device sessions for the given Kratos identity,
// ordered by issued_at descending (most recent first).
func (r *PostgresDeviceSessionRepository) GetDeviceSessions(ctx context.Context, kratosID string) ([]domain.DeviceSession, error) {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	rows, err := r.pool.Query(ctx, `
		SELECT id, kratos_id, device_id, hydra_jti,
		       issued_at, last_used_at, revoked, user_agent, ip_address
		FROM   device_sessions
		WHERE  kratos_id = $1
		ORDER  BY issued_at DESC
	`, kratosID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []domain.DeviceSession
	for rows.Next() {
		var s domain.DeviceSession
		if err := rows.Scan(
			&s.ID, &s.KratosID, &s.DeviceID, &s.HydraJTI,
			&s.IssuedAt, &s.LastUsedAt, &s.Revoked, &s.UserAgent, &s.IP,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// CountActiveDevices returns the number of non-revoked device sessions for the identity.
func (r *PostgresDeviceSessionRepository) CountActiveDevices(ctx context.Context, kratosID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()
	var count int
	err := r.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM   device_sessions
		WHERE  kratos_id = $1 AND revoked = false
	`, kratosID).Scan(&count)
	return count, err
}

// ── ensure compile-time interface satisfaction ────────────────────────────────

var _ DeviceSessionRepository = (*PostgresDeviceSessionRepository)(nil)
