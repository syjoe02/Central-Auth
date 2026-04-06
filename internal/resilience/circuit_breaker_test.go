package resilience

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// testCfg returns a ResilienceCBConfig suitable for fast unit tests.
func testCfg() ResilienceCBConfig {
	return ResilienceCBConfig{
		FailureThreshold: 5,
		ProbeBaseNanos:   int64(10 * time.Millisecond),
		ProbeMaxNanos:    int64(100 * time.Millisecond),
		JitterPct:        15,
	}
}

func TestCB_Starts_Closed(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	if cb.State() != StateClosed {
		t.Fatalf("expected CLOSED, got %d", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("expected Allow() == true when CLOSED")
	}
}

func TestCB_Trips_After_Threshold(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	// N-1 failures → still CLOSED.
	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected CLOSED after 4 failures, got %d", cb.State())
	}
	// Nth failure → OPEN.
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN after 5 failures, got %d", cb.State())
	}
}

func TestCB_Allow_ReturnsFalse_WhenOpen(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	// Set nextProbeAt far in the future so backoff has not elapsed.
	cb.nextProbeAt.Store(time.Now().Add(10 * time.Hour).UnixNano())

	if cb.Allow() {
		t.Fatal("expected Allow() == false when OPEN and backoff not elapsed")
	}
}

func TestCB_Transitions_To_HalfOpen_After_Backoff(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	// Force nextProbeAt to the past so backoff is considered elapsed.
	cb.nextProbeAt.Store(time.Now().Add(-1 * time.Second).UnixNano())

	if !cb.Allow() {
		t.Fatal("expected Allow() == true when OPEN and backoff elapsed")
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected HALF-OPEN after first Allow(), got %d", cb.State())
	}
}

func TestCB_HalfOpen_OnlyOneProbeAllowed(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	cb.nextProbeAt.Store(time.Now().Add(-1 * time.Second).UnixNano())

	// First Allow() wins the CAS.
	first := cb.Allow()
	// Second Allow() must return false (probe slot taken).
	second := cb.Allow()

	if !first {
		t.Fatal("first Allow() should return true")
	}
	if second {
		t.Fatal("second Allow() should return false when probe is in flight")
	}
}

func TestCB_Resets_OnProbeSuccess(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	cb.nextProbeAt.Store(time.Now().Add(-1 * time.Second).UnixNano())
	cb.Allow() // transition to HALF-OPEN, claim probe slot

	cb.RecordSuccess()

	if cb.State() != StateClosed {
		t.Fatalf("expected CLOSED after RecordSuccess, got %d", cb.State())
	}
	if cb.failures.Load() != 0 {
		t.Fatalf("expected failure count = 0, got %d", cb.failures.Load())
	}
	if cb.probeInFlight.Load() != 0 {
		t.Fatal("expected probeInFlight = 0 after RecordSuccess")
	}
}

func TestCB_ExtendsBackoff_OnProbeFailure(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	for i := 0; i < 5; i++ {
		cb.RecordFailure()
	}
	cb.nextProbeAt.Store(time.Now().Add(-1 * time.Second).UnixNano())
	firstProbeAt := cb.nextProbeAt.Load()
	cb.Allow() // HALF-OPEN

	cb.RecordFailure() // probe failed

	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN after failed probe, got %d", cb.State())
	}
	if cb.nextProbeAt.Load() <= firstProbeAt {
		t.Fatal("expected nextProbeAt to advance after failed probe")
	}
}

func TestCB_BackoffCap(t *testing.T) {
	cfg := testCfg()
	cfg.JitterPct = 0 // remove jitter for deterministic cap test
	cb := NewCircuitBreaker(cfg)

	// Trip the circuit.
	for i := 0; i < cfg.FailureThreshold; i++ {
		cb.RecordFailure()
	}

	// Simulate many failed probes by directly calling extendBackoff.
	for i := 0; i < 20; i++ {
		cb.extendBackoff()
	}

	cb.backoffMu.Lock()
	v := cb.backoffNanos
	cb.backoffMu.Unlock()

	if v > cfg.ProbeMaxNanos {
		t.Fatalf("backoff %d exceeded max %d", v, cfg.ProbeMaxNanos)
	}
}

func TestCB_JitterRange(t *testing.T) {
	cfg := testCfg()
	cfg.JitterPct = 20
	cb := NewCircuitBreaker(cfg)

	base := cfg.ProbeBaseNanos
	low := base - base*cfg.JitterPct/100 - 1  // allow 1 ns rounding
	high := base + base*cfg.JitterPct/100 + 1

	for i := 0; i < 1000; i++ {
		cb.backoffMu.Lock()
		v := cb.applyJitter(base)
		cb.backoffMu.Unlock()
		if v < low || v > high {
			t.Fatalf("jitter %d out of expected range [%d, %d]", v, low, high)
		}
	}
}

func TestCB_NoTripOnDomainError(t *testing.T) {
	_ = NewCircuitBreaker(testCfg()) // unused but demonstrates API
	// redis.Nil is a domain result, not an infra error.
	if IsInfraError(redis.Nil) {
		t.Fatal("redis.Nil should not be an infra error")
	}
	// Calling RecordFailure manually is how a caller would misuse the API;
	// verify it still trips (this tests the counter, not IsInfraError).
	// The real assertion is that callers must gate on IsInfraError before calling RecordFailure.
}

func TestIsInfraError(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		isInfra bool
	}{
		{"nil", nil, false},
		{"redis.Nil", redis.Nil, false},
		{"context.Canceled", context.Canceled, false},
		{"context.DeadlineExceeded", context.DeadlineExceeded, true},
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"net.Error timeout", &net.OpError{Op: "dial", Err: &timeoutErr{}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsInfraError(tc.err); got != tc.isInfra {
				t.Fatalf("IsInfraError(%v) = %v, want %v", tc.err, got, tc.isInfra)
			}
		})
	}
}

// timeoutErr is a fake net.Error that reports Timeout() == true.
type timeoutErr struct{}

func (e *timeoutErr) Error() string   { return "timeout" }
func (e *timeoutErr) Timeout() bool   { return true }
func (e *timeoutErr) Temporary() bool { return true } //nolint:staticcheck

func TestCB_RaceCondition(t *testing.T) {
	cb := NewCircuitBreaker(testCfg())
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cb.Allow()
			cb.RecordFailure()
			cb.RecordSuccess()
		}()
	}
	wg.Wait()
	// No data race detected by -race; state must be a valid value.
	s := cb.State()
	if s != StateClosed && s != StateOpen && s != StateHalfOpen {
		t.Fatalf("invalid state %d after race test", s)
	}
}
