package config

import (
	"context"
	"os"

	"github.com/redis/go-redis/v9"
	"github.com/jackc/pgx/v5/pgxpool"
)

var Ctx = context.Background()

func NewRedisClient() *redis.Client {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		// Local
		addr = "localhost:6379"
	}

	return redis.NewClient(&redis.Options{
		Addr: addr,
	})
}

func NewPostgresConn() (*pgxpool.Pool, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// Local
		dsn = "postgres://auth:password@localhost:5432/central_auth?sslmode=disable"
	}
	
	return pgxpool.New(context.Background(), dsn)
}