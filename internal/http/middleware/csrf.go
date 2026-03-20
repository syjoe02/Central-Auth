package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"

	"central-auth/internal/metrics"

	"github.com/gin-gonic/gin"
)

const (
	csrfCookieName = "__csrf"
	csrfHeaderName = "X-CSRF-Token"
	csrfRandBytes  = 16 // 32-character hex random component
)

// CSRFMiddleware implements double-submit cookie CSRF protection.
//
// On every response the middleware issues a __csrf cookie (not HttpOnly so JS
// can read it). State-changing requests (POST/PUT/DELETE/PATCH) must echo the
// cookie value back in the X-CSRF-Token header.
//
// The token is HMAC-SHA256 bound to the current session ID so that a token
// issued in session A cannot be replayed in session B (prevents cross-session
// token injection attacks).
//
// Format: <32-hex-random>-<64-hex-HMAC(secret, sessionID+random)>
func CSRFMiddleware(csrfSecret string) gin.HandlerFunc {
	secretKey := []byte(csrfSecret)

	return func(c *gin.Context) {
		if isStateChangingMethod(c.Request.Method) {
			sessionID := sessionIDFromContext(c)
			headerToken := c.GetHeader(csrfHeaderName)
			cookieToken, _ := c.Cookie(csrfCookieName)

			if headerToken == "" || cookieToken == "" || headerToken != cookieToken {
				metrics.BFFCSRFRejected.Inc()
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF token mismatch"})
				return
			}
			if !validateCSRFToken(secretKey, sessionID, headerToken) {
				metrics.BFFCSRFRejected.Inc()
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid CSRF token"})
				return
			}
		}

		c.Next()

		// Rotate CSRF token on every response to limit reuse window.
		sessionID := sessionIDFromContext(c)
		token, err := newCSRFToken(secretKey, sessionID)
		if err != nil {
			// crypto/rand failure is catastrophic; log and skip cookie rotation.
			// The existing cookie (if any) remains valid for this session.
			log.Printf("[ERROR] CSRF: failed to generate token: %v", err)
			return
		}
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     csrfCookieName,
			Value:    token,
			Path:     "/",
			Secure:   true,
			HttpOnly: false, // Must be readable by JS to set the request header.
			SameSite: http.SameSiteStrictMode,
		})
	}
}

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

func sessionIDFromContext(c *gin.Context) string {
	v, _ := c.Get("sessionID")
	id, _ := v.(string)
	return id
}

// newCSRFToken generates an HMAC-bound CSRF token.
// Returns an error if crypto/rand is unavailable; callers must handle this
// as a hard failure rather than falling back to a deterministic value.
func newCSRFToken(secret []byte, sessionID string) (string, error) {
	b := make([]byte, csrfRandBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	random := hex.EncodeToString(b)
	mac := csrfHMAC(secret, sessionID+random)
	return random + "-" + mac, nil
}

// validateCSRFToken verifies the HMAC binding.
func validateCSRFToken(secret []byte, sessionID, token string) bool {
	// Token format: <32-hex>-<64-hex>
	if len(token) < 34 || token[32] != '-' {
		return false
	}
	random := token[:32]
	expected := csrfHMAC(secret, sessionID+random)
	// Use hmac.Equal for constant-time comparison.
	return hmac.Equal([]byte(token[33:]), []byte(expected))
}

func csrfHMAC(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
