package middleware

import (
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
)

// bffSessionCookieName is the cookie that carries the opaque session ID.
const bffSessionCookieName = "__session"

// sessionIDRegexp validates that a session ID is exactly 64 lowercase hex characters
// (32 random bytes from crypto/rand encoded as hex).
var sessionIDRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BFFSessionMiddleware extracts the BFF session ID from the __session HttpOnly cookie
// and stores it in the Gin context under the key "sessionID".
//
// Aborts with 401 if:
//   - The cookie is absent
//   - The cookie value does not match the expected 64-character hex format
//
// Downstream handlers retrieve the session ID via c.MustGet("sessionID").(string).
func BFFSessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookieVal, err := c.Cookie(bffSessionCookieName)
		if err != nil || cookieVal == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing session"})
			return
		}
		if !sessionIDRegexp.MatchString(cookieVal) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid session format"})
			return
		}
		c.Set("sessionID", cookieVal)
		c.Next()
	}
}
