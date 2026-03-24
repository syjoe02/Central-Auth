package config

import (
	"log"
	"os"
)

// ServerConfig holds server-level secrets validated at startup.
type ServerConfig struct {
	ServiceAPIKey           string
	AppEnv                  string
	MetricsBasicAuthUser    string
	MetricsBasicAuthPassword string
}

// LoadServerConfig validates the service pre-shared key and environment mode.
// Rules:
//   - CENTRAL_AUTH_SERVICE_KEY must always be set (any env).
//   - APP_ENV=production requires the key to be at least 32 characters.
//   - Shorter keys in non-production emit a [WARN] but do not abort.
//
// Uses log.Fatalf (not panic) so the container exits with status 1 and a clean
// single-line message — no stack trace in production logs.
func LoadServerConfig() ServerConfig {
	key := os.Getenv("CENTRAL_AUTH_SERVICE_KEY")
	appEnv := os.Getenv("APP_ENV")

	if key == "" {
		log.Fatalf("[FATAL] CENTRAL_AUTH_SERVICE_KEY env var must be set")
	}
	if appEnv == "production" && len(key) < 32 {
		log.Fatalf("[FATAL] CENTRAL_AUTH_SERVICE_KEY must be at least 32 characters in production (got %d)", len(key))
	}
	if appEnv != "production" && len(key) < 32 {
		log.Printf("[WARN] CENTRAL_AUTH_SERVICE_KEY is %d characters — minimum 32 required for production", len(key))
	}

	// Production DB password check.
	if appEnv == "production" {
		dbPass := os.Getenv("POSTGRES_PASSWORD")
		if dbPass == "" {
			log.Fatalf("[FATAL] POSTGRES_PASSWORD must be set in production")
		}
		if len(dbPass) < 12 {
			log.Fatalf("[FATAL] POSTGRES_PASSWORD must be at least 12 characters in production (got %d)", len(dbPass))
		}
	}

	// Metrics Basic Auth credentials — required in production, optional in dev.
	metricsUser := os.Getenv("METRICS_BASIC_AUTH_USER")
	metricsPass := os.Getenv("METRICS_BASIC_AUTH_PASSWORD")
	if appEnv == "production" {
		if metricsUser == "" || metricsPass == "" {
			log.Fatalf("[FATAL] METRICS_BASIC_AUTH_USER and METRICS_BASIC_AUTH_PASSWORD must be set in production")
		}
		if os.Getenv("METRICS_ALLOWED_CIDR") == "" {
			log.Fatalf("[FATAL] METRICS_ALLOWED_CIDR must be set in production")
		}
	}

	return ServerConfig{
		ServiceAPIKey:            key,
		AppEnv:                   appEnv,
		MetricsBasicAuthUser:     metricsUser,
		MetricsBasicAuthPassword: metricsPass,
	}
}
