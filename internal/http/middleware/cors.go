package middleware

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// LoadCORSOrigins reads CORS_ALLOWED_ORIGINS from the environment (comma-
// separated list of exact origins, e.g. "https://app.example.com").
// In production (appEnv == "production"), an empty value or any wildcard entry
// is a fatal startup error — the server will not bind.
// In non-production, an empty or wildcard value is allowed but logged as [WARN].
// Returns nil when open access is permitted (dev only).
func LoadCORSOrigins(appEnv string) []string {
	raw := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))

	if raw == "" || raw == "*" {
		if appEnv == "production" {
			log.Fatalf("[FATAL] CORS_ALLOWED_ORIGINS must be a non-wildcard whitelist in production")
		}
		log.Println("[WARN] CORS_ALLOWED_ORIGINS not set or is wildcard — all origins allowed; do NOT use in production")
		return nil
	}

	origins := strings.Split(raw, ",")
	for _, o := range origins {
		if strings.TrimSpace(o) == "*" {
			if appEnv == "production" {
				log.Fatalf("[FATAL] Wildcard '*' in CORS_ALLOWED_ORIGINS is not permitted in production")
			}
			log.Println("[WARN] Wildcard '*' in CORS_ALLOWED_ORIGINS; do NOT use in production")
		}
	}

	trimmed := make([]string, 0, len(origins))
	for _, o := range origins {
		if t := strings.TrimSpace(o); t != "" {
			trimmed = append(trimmed, t)
		}
	}
	log.Printf("[INFO] CORS whitelist loaded: %d origin(s)", len(trimmed))
	return trimmed
}

// CORSMiddleware returns a Gin handler enforcing an exact-match origin
// whitelist. Requests from unlisted origins receive no CORS headers (the
// browser will block them). Preflight OPTIONS requests from listed origins
// receive 204. Pass nil allowedOrigins to allow all origins (dev only).
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	// nil → open access (dev fallback, LoadCORSOrigins already warned)
	if allowedOrigins == nil {
		return func(c *gin.Context) {
			origin := c.Request.Header.Get("Origin")
			if origin != "" {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
				c.Header("Access-Control-Allow-Credentials", "true")
				c.Header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Authorization")
				c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		}
	}

	set := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		set[o] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		_, listed := set[origin]

		if origin != "" && listed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Authorization")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}

		if c.Request.Method == http.MethodOptions {
			// Unlisted (or no) origin: deny the preflight rather than returning
			// a bare 204. A 403 avoids confirming that the endpoint is reachable
			// to scanners while still being a well-defined HTTP response.
			if !listed {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
