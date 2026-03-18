package config

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
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
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	db := os.Getenv("POSTGRES_DB")
	sslmode := os.Getenv("POSTGRES_SSLMODE")

	if host == "" {
		// Local fallback
		host = "localhost"
	}
	if sslmode == "" {
		sslmode = "require"
	}

	dsn := "postgres://" + user + ":" + password +
		"@" + host + ":" + port + "/" + db +
		"?sslmode=" + sslmode

	return pgxpool.New(context.Background(), dsn)
}
