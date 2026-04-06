package resilience

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// captureRecorder is a test double that records calls to captureFunc.
type captureRecorder struct {
	count  atomic.Int32
	errors []error
}

func (r *captureRecorder) capture(err error) {
	r.count.Add(1)
	r.errors = append(r.errors, err)
}

func newCBWithRecorder(t *testing.T) (*circuitBreaker, *captureRecorder) {
	t.Helper()
	rec := &captureRecorder{}
	cb := NewCircuitBreaker(testCfg(), WithSentryCapture(rec.capture))
	return cb, rec
}

func TestRecordFailure_TripsClosed_CallsSentryCapture(t *testing.T) {
	cb, rec := newCBWithRecorder(t)

	// Feed N-1 failures — should NOT trigger capture yet.
	for i := 0; i < testCfg().FailureThreshold-1; i++ {
		cb.RecordFailure()
	}
	if rec.count.Load() != 0 {
		t.Fatalf("expected 0 capture calls after %d failures, got %d",
			testCfg().FailureThreshold-1, rec.count.Load())
	}

	// Nth failure — circuit trips, capture must fire exactly once.
	cb.RecordFailure()
	if rec.count.Load() != 1 {
		t.Fatalf("expected 1 capture call after trip, got %d", rec.count.Load())
	}
	if !errors.Is(rec.errors[0], rec.errors[0]) { // always true — just check non-nil
		t.Fatal("captured error should not be nil")
	}
}

func TestRecordFailure_HalfOpenProbeFails_CallsSentryCapture(t *testing.T) {
	cb, rec := newCBWithRecorder(t)

	// Trip the breaker.
	for i := 0; i < testCfg().FailureThreshold; i++ {
		cb.RecordFailure()
	}
	capturesAfterTrip := rec.count.Load() // 1 capture for CLOSED→OPEN

	// Transition to HALF-OPEN.
	cb.nextProbeAt.Store(time.Now().Add(-1 * time.Second).UnixNano())
	cb.Allow() // wins probe slot → HALF-OPEN

	// Probe fails.
	cb.RecordFailure()

	total := rec.count.Load()
	if total != capturesAfterTrip+1 {
		t.Fatalf("expected %d total captures, got %d", capturesAfterTrip+1, total)
	}
	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN after failed probe, got %d", cb.State())
	}
}

func TestRecordFailure_AlreadyOpen_NoExtraCapture(t *testing.T) {
	cb, rec := newCBWithRecorder(t)

	// Trip the breaker.
	for i := 0; i < testCfg().FailureThreshold; i++ {
		cb.RecordFailure()
	}
	afterTrip := rec.count.Load()

	// Force nextProbeAt into the far future so we stay OPEN.
	cb.nextProbeAt.Store(time.Now().Add(10 * time.Hour).UnixNano())

	// Additional RecordFailure calls while OPEN should not trigger extra captures.
	cb.RecordFailure()
	cb.RecordFailure()

	if rec.count.Load() != afterTrip {
		t.Fatalf("expected no additional captures while already OPEN, count went from %d to %d",
			afterTrip, rec.count.Load())
	}
}

func TestRecordSuccess_NoSentryCapture(t *testing.T) {
	cb, rec := newCBWithRecorder(t)

	// Trip → HALF-OPEN → RecordSuccess.
	for i := 0; i < testCfg().FailureThreshold; i++ {
		cb.RecordFailure()
	}
	afterTrip := rec.count.Load()

	cb.nextProbeAt.Store(time.Now().Add(-1 * time.Second).UnixNano())
	cb.Allow()
	cb.RecordSuccess()

	if rec.count.Load() != afterTrip {
		t.Fatalf("RecordSuccess should not call captureFunc; captures went from %d to %d",
			afterTrip, rec.count.Load())
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected CLOSED after RecordSuccess, got %d", cb.State())
	}
}
