package middleware

import (
	"crypto/subtle"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func ServiceAuthMiddleware() gin.HandlerFunc {
	expected := []byte(os.Getenv("SERVICE_API_KEY"))

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
