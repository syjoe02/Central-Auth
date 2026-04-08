package interceptor

import (
	"sync"
	"time"
)

// tokenBucket is a simple in-process token bucket rate limiter.
// For multi-instance deployments, replace with a Redis-backed implementation.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	refillPS float64 // tokens per second
	lastTick time.Time
}

func newTokenBucket(requestsPerMinute int) *tokenBucket {
	rps := float64(requestsPerMinute) / 60.0
	return &tokenBucket{
		tokens:   float64(requestsPerMinute),
		max:      float64(requestsPerMinute),
		refillPS: rps,
		lastTick: time.Now(),
	}
}

// Allow returns true and consumes one token if available.
func (tb *tokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTick).Seconds()
	tb.lastTick = now

	tb.tokens += elapsed * tb.refillPS
	if tb.tokens > tb.max {
		tb.tokens = tb.max
	}
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}
