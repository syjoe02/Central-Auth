package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresAuthUserRepository struct {
	db *pgxpool.Pool
}

func NewPostgresAuthUserRepository(db *pgxpool.Pool) *PostgresAuthUserRepository {
	return &PostgresAuthUserRepository{
		db: db,
	}
}

func (r *PostgresAuthUserRepository) FindByProvider(provider, providerUserID string) (*AuthUser, error) {
	const query = `
		SELECT user_id, provider, provider_user_id, email
		FROM auth_users
		WHERE provider = $1 AND provider_user_id = $2
	`

	row := r.db.QueryRow(context.Background(), query, provider, providerUserID)

	var user AuthUser
	err := row.Scan(&user.UserID, &user.Provider, &user.ProviderUserID, &user.Email)
	if err != nil {
		// row 없으면 nil 리턴
		return nil, nil
	}

	return &user, nil
}

func (r *PostgresAuthUserRepository) Create(user *AuthUser) error {
	const query = `
		INSERT INTO auth_users (user_id, provider, provider_user_id, email)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.db.Exec(
		context.Background(),
		query,
		user.UserID,
		user.Provider,
		user.ProviderUserID,
		user.Email,
	)
	return err
}