package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

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

	// Log only the host:port — never log the full DSN or any password.
	log.Printf("[INFO] Redis client connecting to %s", addr)

	return redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  time.Duration(envInt("REDIS_DIAL_TIMEOUT_MS", 100)) * time.Millisecond,
		ReadTimeout:  time.Duration(envInt("REDIS_READ_TIMEOUT_MS", 500)) * time.Millisecond,
		WriteTimeout: time.Duration(envInt("REDIS_WRITE_TIMEOUT_MS", 500)) * time.Millisecond,
	})
}

// PostgresDSN constructs the postgres:// connection string from environment
// variables. It is exported so that callers such as the migration runner can
// obtain the DSN without also creating a pgxpool.
func PostgresDSN() string {
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	db := os.Getenv("POSTGRES_DB")
	sslmode := os.Getenv("POSTGRES_SSLMODE")

	if host == "" {
		host = "localhost"
	}
	if sslmode == "" {
		sslmode = "require"
	}

	return "postgres://" + user + ":" + password +
		"@" + host + ":" + port + "/" + db +
		"?sslmode=" + sslmode
}

func NewPostgresConn() (*pgxpool.Pool, error) {
	dsn := PostgresDSN()

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}

	poolCfg.MaxConns = int32(envInt("POSTGRES_POOL_MAX_CONNS", 25))
	poolCfg.MinConns = int32(envInt("POSTGRES_POOL_MIN_CONNS", 5))
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 1 * time.Minute

	return pgxpool.NewWithConfig(context.Background(), poolCfg)
}

// envInt reads an integer environment variable, returning fallback if absent or invalid.
func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}
