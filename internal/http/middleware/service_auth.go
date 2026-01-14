package middleware

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func ServiceAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceKey := c.GetHeader("X-Service-Key")
		if serviceKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing service key",
			})
			return
		}

		if serviceKey != os.Getenv("SERVICE_API_KEY") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid service key",
			})
			return
		}

		c.Next()
	}
}