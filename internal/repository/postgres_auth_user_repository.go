package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"central-auth/internal/domain"
)

type PostgresAuthUserRepository struct {
	db *pgxpool.Pool
}

func NewPostgresAuthUserRepository(db *pgxpool.Pool) AuthUserRepository {
	return &PostgresAuthUserRepository{db: db}
}

// AuthUser
func (r *PostgresAuthUserRepository) FindByProvider(
	provider, providerID string,
) (*domain.AuthUser, error) {

	const query = `
		SELECT user_id, provider, provider_user_id, email
		FROM auth_users
		WHERE provider = $1 AND provider_user_id = $2
	`

	row := r.db.QueryRow(context.Background(), query, provider, providerID)

	var u domain.AuthUser
	err := row.Scan(&u.UserID, &u.Provider, &u.ProviderID, &u.Email)
	if err != nil {
		return nil, nil
	}
	return &u, nil
}

func (r *PostgresAuthUserRepository) Save(user *domain.AuthUser) error {
	const query = `
		INSERT INTO auth_users (user_id, provider, provider_user_id, email)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO NOTHING
	`
	_, err := r.db.Exec(context.Background(), query,
		user.UserID, user.Provider, user.ProviderID, user.Email)
	return err
}

// Refresh Token
func (r *PostgresAuthUserRepository) SaveRefreshToken(
	ctx context.Context,
	token *domain.RefreshToken,
) error {

	const query = `
		INSERT INTO refresh_tokens
		(user_id, device_id, token_hash, issued_at, expires_at, revoked,
		 user_agent, ip_address, last_used_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (user_id, device_id)
		DO UPDATE SET
			token_hash   = EXCLUDED.token_hash,
			issued_at    = EXCLUDED.issued_at,
			expires_at   = EXCLUDED.expires_at,
			revoked      = false,
			user_agent   = EXCLUDED.user_agent,
			ip_address   = EXCLUDED.ip_address,
			last_used_at = NULL
		`

	_, err := r.db.Exec(
		ctx,
		query,
		token.UserID,
		token.DeviceID,
		token.TokenHash,
		token.IssuedAt,
		token.ExpiresAt,
		token.Revoked,
		token.UserAgent,
		token.IP,
		token.LastUsedAt,
	)
	return err
}

// Device Info
func (r *PostgresAuthUserRepository) GetLoginDevices(
	ctx context.Context,
	userID string,
) ([]domain.LoginDeviceInfo, error) {

	const query = `
		SELECT device_id, user_agent, ip_address,
		       issued_at, expires_at, last_used_at, revoked
		FROM refresh_tokens
		WHERE user_id = $1
		ORDER BY issued_at DESC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []domain.LoginDeviceInfo

	for rows.Next() {
		var info domain.LoginDeviceInfo
		err := rows.Scan(
			&info.DeviceID,
			&info.UserAgent,
			&info.IPAddress,
			&info.IssuedAt,
			&info.ExpiresAt,
			&info.LastUsedAt,
			&info.Revoked,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, info)
	}

	return result, nil
}

func (r *PostgresAuthUserRepository) CountActiveDevices(
	ctx context.Context,
	userID string,
) (int, error) {

	const q = `
		SELECT COUNT(*)
		FROM refresh_tokens
		WHERE user_id = $1
		  AND revoked = false
		  AND expires_at > NOW()
	`

	var count int
	err := r.db.QueryRow(ctx, q, userID).Scan(&count)
	return count, err
}

// Update & Revoke
func (r *PostgresAuthUserRepository) UpdateLastUsedAt(
	ctx context.Context,
	userID string,
	deviceID string,
) error {
	const q = `
		UPDATE refresh_tokens
		SET last_used_at = NOW()
		WHERE user_id = $1 AND device_id = $2 AND revoked = false
	`
	_, err := r.db.Exec(ctx, q, userID, deviceID)
	return err
}

func (r *PostgresAuthUserRepository) RevokeDevice(
	ctx context.Context,
	userID string,
	deviceID string,
) error {
	const q = `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE user_id = $1 AND device_id = $2
	`
	_, err := r.db.Exec(ctx, q, userID, deviceID)
	return err
}

func (r *PostgresAuthUserRepository) RevokeAllDevices(
	ctx context.Context,
	userID string,
) error {
	const q = `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE user_id = $1
	`
	_, err := r.db.Exec(ctx, q, userID)
	return err
}
