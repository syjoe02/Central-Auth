package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	rateLimitRequests = 20
	rateLimitWindow   = time.Minute
)

type bucket struct {
	mu          sync.Mutex
	count       int
	windowStart time.Time
}

var ipBuckets sync.Map

// RateLimitMiddleware limits each client IP to rateLimitRequests per rateLimitWindow.
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		v, _ := ipBuckets.LoadOrStore(ip, &bucket{windowStart: now})
		b := v.(*bucket)

		b.mu.Lock()
		if now.Sub(b.windowStart) >= rateLimitWindow {
			b.count = 0
			b.windowStart = now
		}
		b.count++
		over := b.count > rateLimitRequests
		b.mu.Unlock()

		if over {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}
