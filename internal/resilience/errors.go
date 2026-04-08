// Package resilience provides a Redis circuit breaker with L1 in-process cache
// and PostgreSQL fallback for the Central-Auth service.
package resilience

import "errors"

// ErrRedisUnavailable is returned to callers when the circuit breaker is OPEN
// and the operation cannot be served from L1 cache or the PostgreSQL fallback.
// Callers that can tolerate degraded state (e.g. write operations during outage)
// should treat this as a warning rather than a hard failure.
var ErrRedisUnavailable = errors.New("redis unavailable")
