package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ServiceAuthMiddleware validates the X-Service-Key header against the
// provided serviceKey value. The caller (main) is responsible for reading the
// key from config so this middleware does not access environment variables
// directly.
func ServiceAuthMiddleware(serviceKey string) gin.HandlerFunc {
	expected := []byte(serviceKey)

	return func(c *gin.Context) {
		serviceKey := c.GetHeader("X-Service-Key")
		if serviceKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing service key",
			})
			return
		}

		if subtle.ConstantTimeCompare([]byte(serviceKey), expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid service key",
			})
			return
		}

		c.Next()
	}
}
