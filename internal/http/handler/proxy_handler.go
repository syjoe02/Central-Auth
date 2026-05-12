package handler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"central-auth/internal/hydra"
)

// authFreePrefixes are proxied to Django without requiring a valid access token.
// These paths are handled by Django's own auth middleware (login, signup, refresh)
// or are public endpoints.
var authFreePrefixes = []string{
	"/api/auth/",
}

// ProxyHandler validates the caller's Hydra access token then reverse-proxies
// the request to the Django backend. On authenticated routes it injects an
// Authorization: Bearer header so Django's JWKS middleware can re-validate
// without touching a cookie.
type ProxyHandler struct {
	proxy       *httputil.ReverseProxy
	hydraClient hydra.ClientI
}

// NewProxyHandler constructs a ProxyHandler that forwards traffic to djangoURL.
func NewProxyHandler(djangoURL string, dialTimeout time.Duration, hydraClient hydra.ClientI) (*ProxyHandler, error) {
	target, err := url.Parse(djangoURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid DJANGO_URL %q: %w", djangoURL, err)
	}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport

	// Return 503 instead of leaking a timeout or "connection refused" body.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, `{"error":"upstream unavailable"}`, http.StatusServiceUnavailable)
	}

	// Log 409 conflicts at INFO level — duplicate signups are expected under load.
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusConflict {
			slog.Info("upstream conflict", "method", resp.Request.Method, "path", resp.Request.URL.Path)
		}
		return nil
	}

	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		// Rewrite Host so Django's ALLOWED_HOSTS accepts the request.
		req.Host = target.Host
	}

	return &ProxyHandler{proxy: proxy, hydraClient: hydraClient}, nil
}

// Handle is the Gin handler for all /api/* routes.
// Authenticated routes: validate Hydra JWT locally (cached JWKS, zero network
// calls on hot path) then inject trusted headers before forwarding to Django/Kotlin.
// Auth-free routes (/api/auth/*): forwarded as-is.
func (h *ProxyHandler) Handle(c *gin.Context) {
	path := c.Request.URL.Path

	// Strip spoof-able identity headers unconditionally.
	// They are only re-added below after successful JWT validation.
	c.Request.Header.Del("X-User-ID")
	c.Request.Header.Del("X-Device-ID")

	// Propagate or generate a Correlation-ID for distributed tracing.
	if c.Request.Header.Get("X-Correlation-ID") == "" {
		c.Request.Header.Set("X-Correlation-ID", newCorrelationID())
	}

	if !isAuthFree(path) {
		token := extractBearerToken(c.Request)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		claims, err := h.hydraClient.ValidateAccessToken(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// Normalise to header so downstream JWKS middleware reads it from one place.
		c.Request.Header.Set("Authorization", "Bearer "+token)
		// Convenience headers — downstream services can read these without re-decoding the JWT.
		c.Request.Header.Set("X-User-ID", claims.Subject)
		if deviceID := claims.DeviceID(); deviceID != "" {
			c.Request.Header.Set("X-Device-ID", deviceID)
		}
	}

	h.proxy.ServeHTTP(c.Writer, c.Request)
}

// newCorrelationID generates a 16-byte random hex string for request tracing.
func newCorrelationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "fallback-correlation-id"
	}
	return hex.EncodeToString(b)
}

// isAuthFree returns true when the path should be forwarded without token validation.
func isAuthFree(path string) bool {
	for _, prefix := range authFreePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// extractBearerToken reads the access token from the Authorization: Bearer header
// first, then falls back to the access_token httpOnly cookie set by Django's
// LoginAPIView. Locust's HttpSession propagates cookies automatically.
func extractBearerToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	if cookie, err := r.Cookie("access_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}
