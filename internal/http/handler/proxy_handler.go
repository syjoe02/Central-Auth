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
)

// authFreePrefixes are proxied to backendKotlin without an authenticated BFF
// session being required. These paths are public or handled by backendKotlin's
// own logic (e.g. signup).
var authFreePrefixes = []string{
	"/api/auth/",
}

// ProxyHandler validates the BFF session context set by BFFAPIBridgeMiddleware
// and reverse-proxies the request to the Kotlin backend. It injects a service
// key so BackendKotlin can trust that the request originated from Central-auth.
type ProxyHandler struct {
	proxy      *httputil.ReverseProxy
	serviceKey string
}

// NewProxyHandler constructs a ProxyHandler that forwards traffic to kotlinURL.
// serviceKey is sent as X-Service-Key on every proxied request so BackendKotlin
// can verify the request originated from this trusted BFF.
func NewProxyHandler(kotlinURL string, dialTimeout time.Duration, serviceKey string) (*ProxyHandler, error) {
	if serviceKey == "" {
		return nil, fmt.Errorf("proxy: serviceKey must not be empty")
	}

	target, err := url.Parse(kotlinURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid KOTLIN_URL %q: %w", kotlinURL, err)
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
		// Rewrite Host to match the backendKotlin service address.
		req.Host = target.Host
	}

	return &ProxyHandler{proxy: proxy, serviceKey: serviceKey}, nil
}

// Handle is the Gin handler for all /api/* routes.
// Strips all incoming identity/auth headers unconditionally (prevents spoofing),
// then re-injects X-User-ID and X-Device-ID from the trusted BFF session context
// set by BFFAPIBridgeMiddleware, and adds X-Service-Key so BackendKotlin can
// verify this request came from Central-auth.
// Auth-free routes (/api/auth/*): forwarded without requiring a resolved session.
// All other routes: require a resolved BFF session (X-User-ID must be set).
func (h *ProxyHandler) Handle(c *gin.Context) {
	path := c.Request.URL.Path

	// Strip ALL spoof-able identity/auth headers unconditionally — even on auth-free
	// paths — so a malicious caller cannot inject trusted headers directly.
	c.Request.Header.Del("X-User-ID")
	c.Request.Header.Del("X-Device-ID")
	c.Request.Header.Del("X-Service-Key")
	c.Request.Header.Del("Authorization")

	// Propagate or generate a Correlation-ID for distributed tracing.
	if c.Request.Header.Get("X-Correlation-ID") == "" {
		c.Request.Header.Set("X-Correlation-ID", newCorrelationID())
	}

	// Always inject service key so BackendKotlin knows this came from Central-auth.
	c.Request.Header.Set("X-Service-Key", h.serviceKey)

	if !isAuthFree(path) {
		userID, exists := c.Get("bff.userID")
		if !exists || userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		c.Request.Header.Set("X-User-ID", userID.(string))
		if deviceID, ok := c.Get("bff.deviceID"); ok && deviceID != "" {
			c.Request.Header.Set("X-Device-ID", deviceID.(string))
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

// isAuthFree returns true when the path should be forwarded without a BFF session.
func isAuthFree(path string) bool {
	for _, prefix := range authFreePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
