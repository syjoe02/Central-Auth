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
	// bucketEvictInterval controls how often stale IP buckets are swept.
	// Stale = no request in the last 2× window. At 20 req/min this keeps
	// memory bounded even under port-scan traffic.
	bucketEvictInterval = 5 * time.Minute
)

type bucket struct {
	mu          sync.Mutex
	count       int
	windowStart time.Time
}

// rateLimiter holds per-IP buckets and runs a background eviction goroutine.
// Embedding the map in the struct (rather than using a package-level variable)
// makes the middleware testable in isolation and prevents state leaking between
// test cases.
type rateLimiter struct {
	buckets sync.Map
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{}
	go rl.evictLoop()
	return rl
}

// evictLoop runs forever, periodically deleting buckets whose window has
// long since passed. This bounds memory growth when unique IPs accumulate.
func (rl *rateLimiter) evictLoop() {
	ticker := time.NewTicker(bucketEvictInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rl.buckets.Range(func(k, v any) bool {
			b := v.(*bucket)
			b.mu.Lock()
			stale := now.Sub(b.windowStart) > 2*rateLimitWindow
			b.mu.Unlock()
			if stale {
				rl.buckets.Delete(k)
			}
			return true
		})
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	now := time.Now()
	v, _ := rl.buckets.LoadOrStore(ip, &bucket{windowStart: now})
	b := v.(*bucket)

	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.windowStart) >= rateLimitWindow {
		b.count = 0
		b.windowStart = now
	}
	b.count++
	return b.count <= rateLimitRequests
}

// defaultLimiter is the shared limiter used by RateLimitMiddleware().
// It is initialised once at program startup.
var defaultLimiter = newRateLimiter()

// RateLimitMiddleware limits each client IP to rateLimitRequests per rateLimitWindow.
// The backing limiter is shared across calls so multiple route registrations share
// a single counter per IP. Stale buckets are evicted every bucketEvictInterval to
// prevent unbounded memory growth.
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !defaultLimiter.allow(c.ClientIP()) {
			c.Header("Retry-After", rateLimitWindow.String())
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}
