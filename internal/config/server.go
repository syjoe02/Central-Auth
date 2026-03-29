package config

import (
	"log"
	"os"
	"strings"
)

// ServerConfig holds server-level secrets validated at startup.
type ServerConfig struct {
	ServiceAPIKey            string
	AppEnv                   string
	MetricsBasicAuthUser     string
	MetricsBasicAuthPassword string
	// TrustedProxyCIDRs is passed to gin.SetTrustedProxies to prevent
	// X-Forwarded-For spoofing. Defaults to the Docker bridge subnet.
	TrustedProxyCIDRs []string
}

// splitAndTrim splits a comma-separated string and trims whitespace from each element.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
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

	// TRUSTED_PROXY_CIDRS is a comma-separated list of CIDR ranges for upstream
	// proxies. If unset, the Docker default bridge subnet is used.
	trustedCIDRs := []string{"172.16.0.0/12"} // Docker bridge default
	if v := os.Getenv("TRUSTED_PROXY_CIDRS"); v != "" {
		trustedCIDRs = splitAndTrim(v)
	}

	return ServerConfig{
		ServiceAPIKey:            key,
		AppEnv:                   appEnv,
		MetricsBasicAuthUser:     metricsUser,
		MetricsBasicAuthPassword: metricsPass,
		TrustedProxyCIDRs:        trustedCIDRs,
	}
}
