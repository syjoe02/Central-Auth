package config

import (
	"log"
	"os"
	"time"
)

// BFFConfig holds all configuration for the BFF session layer.
type BFFConfig struct {
	CookieDomain             string
	CookieSecure             bool
	SessionTTL               time.Duration
	CSRFSecret               string
	JWKSGracePeriod          time.Duration
	AccessTokenRefreshBuffer time.Duration
}

// LoadBFFConfig reads BFF configuration from environment variables.
// Panics if required variables are missing.
func LoadBFFConfig() BFFConfig {
	csrfSecret := os.Getenv("BFF_CSRF_SECRET")
	if csrfSecret == "" {
		panic("BFF_CSRF_SECRET env var must be set")
	}
	cookieDomain := os.Getenv("BFF_COOKIE_DOMAIN")
	if cookieDomain == "" {
		panic("BFF_COOKIE_DOMAIN env var must be set")
	}

	secure := true
	if os.Getenv("BFF_COOKIE_SECURE") == "false" {
		secure = false
		log.Println("[WARN] BFF_COOKIE_SECURE=false — session cookies will be sent over plain HTTP; do NOT use in production")
	}

	sessionTTL := 7 * 24 * time.Hour
	if v := os.Getenv("BFF_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			sessionTTL = d
		}
	}

	const maxGracePeriod = 2 * time.Hour
	gracePeriod := 30 * time.Minute
	if v := os.Getenv("BFF_JWKS_GRACE_PERIOD"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			gracePeriod = d
		}
	}
	if gracePeriod > maxGracePeriod {
		panic("BFF_JWKS_GRACE_PERIOD exceeds maximum allowed value of 2h — check for misconfiguration")
	}

	refreshBuffer := 60 * time.Second
	if v := os.Getenv("BFF_ACCESS_TOKEN_REFRESH_BUFFER"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			refreshBuffer = d
		}
	}

	return BFFConfig{
		CookieDomain:             cookieDomain,
		CookieSecure:             secure,
		SessionTTL:               sessionTTL,
		CSRFSecret:               csrfSecret,
		JWKSGracePeriod:          gracePeriod,
		AccessTokenRefreshBuffer: refreshBuffer,
	}
}
