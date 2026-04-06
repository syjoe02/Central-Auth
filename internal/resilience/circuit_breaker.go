package resilience

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/redis/go-redis/v9"
)

// State represents the three FSM states of the circuit breaker.
type State int32

const (
	StateClosed   State = 0 // Normal: all operations routed to Redis.
	StateOpen     State = 1 // Degraded: Redis not contacted; L1/PG fallback used.
	StateHalfOpen State = 2 // Probing: one goroutine allowed to test Redis health.
)

// CircuitBreaker is the public contract consumed by the resilient wrappers.
// All methods are safe for concurrent use.
type CircuitBreaker interface {
	// Allow returns true when the caller may attempt a Redis operation.
	// CLOSED: always true. OPEN: false until backoff elapses, then one goroutine
	// wins the CAS and gets true for the probe. HALF-OPEN: only the probe goroutine.
	Allow() bool
	// RecordSuccess resets the failure counter and transitions HALF-OPEN → CLOSED.
	RecordSuccess()
	// RecordFailure increments the failure counter. Trips CLOSED → OPEN at threshold,
	// or re-opens and extends backoff when called from HALF-OPEN.
	RecordFailure()
	// State returns the current FSM state for observability and testing.
	State() State
}

// CBOption is a functional option for NewCircuitBreaker.
type CBOption func(*circuitBreaker)

// WithSentryCapture overrides the function called when the circuit transitions
// CLOSED→OPEN or when a HALF-OPEN probe fails. The default is sentry.CaptureException.
// Inject a no-op or recording function in tests.
func WithSentryCapture(fn func(error)) CBOption {
	return func(cb *circuitBreaker) { cb.captureFunc = fn }
}

// circuitBreaker is the lock-free implementation of CircuitBreaker.
// The only mutex is backoffMu which guards the int64 read-modify-write on backoffNanos;
// that path is rarely executed (only on state transitions).
type circuitBreaker struct {
	// FSM state — StateClosed / StateOpen / StateHalfOpen.
	state atomic.Int32
	// failures counts consecutive infrastructure errors while CLOSED.
	failures atomic.Int32
	// probeInFlight is 0 (no probe) or 1 (probe slot taken). CAS gate for HALF-OPEN.
	probeInFlight atomic.Int32
	// nextProbeAt is a Unix nanosecond timestamp. When now >= nextProbeAt the
	// breaker may transition OPEN → HALF-OPEN inside Allow().
	nextProbeAt atomic.Int64

	backoffMu    sync.Mutex
	backoffNanos int64 // current probe interval in nanoseconds

	cfg         ResilienceCBConfig
	rng         *rand.Rand    // per-instance RNG seeded at construction (not shared)
	captureFunc func(err error) // injected error reporter; default: sentry.CaptureException
}

// ResilienceCBConfig holds the numeric config needed by the circuit breaker.
// Derived from config.ResilienceConfig by the constructor.
type ResilienceCBConfig struct {
	FailureThreshold int
	ProbeBaseNanos   int64
	ProbeMaxNanos    int64
	JitterPct        int64
}

// NewCircuitBreaker constructs a circuit breaker using the provided config.
// Optional CBOption functions can be provided to override defaults (e.g. for testing).
func NewCircuitBreaker(cfg ResilienceCBConfig, opts ...CBOption) *circuitBreaker {
	cb := &circuitBreaker{
		cfg:         cfg,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec // non-crypto RNG fine for jitter
		captureFunc: func(err error) { sentry.CaptureException(err) },
	}
	cb.state.Store(int32(StateClosed))
	for _, opt := range opts {
		opt(cb)
	}
	return cb
}

// Allow implements CircuitBreaker.
func (cb *circuitBreaker) Allow() bool {
	switch State(cb.state.Load()) {
	case StateClosed:
		return true

	case StateOpen:
		if time.Now().UnixNano() < cb.nextProbeAt.Load() {
			return false // backoff not elapsed yet
		}
		// Backoff elapsed — attempt transition OPEN → HALF-OPEN.
		if !cb.state.CompareAndSwap(int32(StateOpen), int32(StateHalfOpen)) {
			return false // another goroutine won the CAS
		}
		CBState.Set(2)
		// Fall through to HALF-OPEN branch to claim the probe slot.
		fallthrough

	case StateHalfOpen:
		// Only one goroutine may probe at a time.
		return cb.probeInFlight.CompareAndSwap(0, 1)
	}
	return false
}

// RecordSuccess implements CircuitBreaker.
func (cb *circuitBreaker) RecordSuccess() {
	cb.probeInFlight.Store(0)
	cb.failures.Store(0)
	cb.state.Store(int32(StateClosed))
	CBState.Set(0)
}

// RecordFailure implements CircuitBreaker.
func (cb *circuitBreaker) RecordFailure() {
	switch State(cb.state.Load()) {
	case StateHalfOpen:
		// Probe failed — re-open and extend backoff.
		cb.probeInFlight.Store(0)
		cb.extendBackoff()
		cb.nextProbeAt.Store(time.Now().UnixNano() + cb.loadBackoff())
		cb.state.Store(int32(StateOpen))
		CBState.Set(1)
		if cb.captureFunc != nil {
			cb.captureFunc(errors.New("redis circuit breaker: HALF-OPEN probe failed, returning to OPEN"))
		}

	case StateClosed:
		n := cb.failures.Add(1)
		if int(n) >= cb.cfg.FailureThreshold {
			if cb.state.CompareAndSwap(int32(StateClosed), int32(StateOpen)) {
				cb.resetBackoff()
				cb.nextProbeAt.Store(time.Now().UnixNano() + cb.loadBackoff())
				CBTripsTotal.Inc()
				CBState.Set(1)
				if cb.captureFunc != nil {
					cb.captureFunc(errors.New("redis circuit breaker tripped: CLOSED→OPEN after failure threshold"))
				}
			}
		}
	// StateOpen: ignore — failures while already open don't restart the timer.
	}
}

// State implements CircuitBreaker.
func (cb *circuitBreaker) State() State {
	return State(cb.state.Load())
}

// ── backoff helpers ────────────────────────────────────────────────────────────

func (cb *circuitBreaker) loadBackoff() int64 {
	cb.backoffMu.Lock()
	v := cb.backoffNanos
	cb.backoffMu.Unlock()
	return v
}

// resetBackoff sets backoffNanos to the base interval plus initial jitter.
// Called when the circuit first trips CLOSED → OPEN.
func (cb *circuitBreaker) resetBackoff() {
	cb.backoffMu.Lock()
	defer cb.backoffMu.Unlock()
	cb.backoffNanos = cb.applyJitter(cb.cfg.ProbeBaseNanos)
}

// extendBackoff doubles backoffNanos (capped at ProbeMaxNanos) and adds jitter.
// Called when a HALF-OPEN probe fails.
func (cb *circuitBreaker) extendBackoff() {
	cb.backoffMu.Lock()
	defer cb.backoffMu.Unlock()
	doubled := cb.backoffNanos * 2
	if doubled > cb.cfg.ProbeMaxNanos {
		doubled = cb.cfg.ProbeMaxNanos
	}
	cb.backoffNanos = cb.applyJitter(doubled)
}

// applyJitter returns base ± (base * JitterPct / 100) using the instance RNG.
// Must be called with backoffMu held (shares cb.rng).
func (cb *circuitBreaker) applyJitter(base int64) int64 {
	jitterRange := base * cb.cfg.JitterPct / 100
	if jitterRange == 0 {
		return base
	}
	// rand.Int63n panics on n==0, guarded above.
	delta := cb.rng.Int63n(jitterRange*2+1) - jitterRange
	return base + delta
}

// ── infrastructure error classifier ───────────────────────────────────────────

// IsInfraError returns true for errors that indicate a Redis infrastructure
// problem (network timeout, connection refused, EOF). It returns false for
// domain results like redis.Nil (key not found) or caller-cancelled contexts.
// Only infrastructure errors should trip the circuit breaker.
func IsInfraError(err error) bool {
	if err == nil {
		return false
	}
	// Domain result — not an infrastructure failure.
	if errors.Is(err, redis.Nil) {
		return false
	}
	// Caller-cancelled context is not a Redis infrastructure failure.
	if errors.Is(err, context.Canceled) {
		return false
	}
	// Network timeout or temporary error.
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) { //nolint:staticcheck
		return true
	}
	// Syscall-level connection errors.
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	// EOF variants (broker closed the connection).
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// Deadline exceeded at the context level (Redis timed out).
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}
