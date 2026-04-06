package resilience

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	gocache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
)

// erroringBlacklist is a fake Blacklist whose IsBlacklisted always returns a
// configurable error. Used to drive infra-error scenarios.
type erroringBlacklist struct {
	callCount int
	err       error
}

func (e *erroringBlacklist) IsBlacklisted(_ context.Context, _ string) (bool, error) {
	e.callCount++
	return false, e.err
}
func (e *erroringBlacklist) Add(_ context.Context, _ string, _ time.Duration) error {
	return e.err
}
func (e *erroringBlacklist) AddBatch(_ context.Context, _ []string, _ time.Duration) error {
	return e.err
}

// ── table-driven: infra errors trip the breaker ────────────────────────────────

func TestInfraErrors_TripBreaker_AfterThreshold(t *testing.T) {
	threshold := 3 // use a small threshold for test speed

	infraErrors := []struct {
		name string
		err  error
	}{
		{"io.EOF", io.EOF},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF},
		{"syscall.ECONNRESET", syscall.ECONNRESET},
		{"syscall.ECONNREFUSED", syscall.ECONNREFUSED},
		{"context.DeadlineExceeded", context.DeadlineExceeded},
		{"net timeout", &net.OpError{Op: "dial", Err: &timeoutErr{}}},
	}

	for _, tc := range infraErrors {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := testCfg()
			cfg.FailureThreshold = threshold
			cb := NewCircuitBreaker(cfg, WithSentryCapture(func(error) {})) // suppress real sentry

			delegate := &erroringBlacklist{err: tc.err}
			bl := NewResilientBlacklist(delegate, cb, gocache.New(1*time.Minute, 2*time.Minute), &fakePgBlacklist{})

			for i := 0; i < threshold; i++ {
				_, _ = bl.IsBlacklisted(context.Background(), "sess-x")
			}

			if cb.State() != StateOpen {
				t.Fatalf("[%s] expected StateOpen after %d infra errors, got %d",
					tc.name, threshold, cb.State())
			}
		})
	}
}

// ── table-driven: non-infra errors do NOT trip the breaker ────────────────────

func TestNonInfraErrors_DoNotTripBreaker(t *testing.T) {
	threshold := 3

	domainErrors := []struct {
		name string
		err  error
	}{
		{"redis.Nil", redis.Nil},
		{"context.Canceled", context.Canceled},
		{"generic domain error", errors.New("not found")},
	}

	for _, tc := range domainErrors {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := testCfg()
			cfg.FailureThreshold = threshold
			cb := NewCircuitBreaker(cfg, WithSentryCapture(func(error) {}))

			delegate := &erroringBlacklist{err: tc.err}
			bl := NewResilientBlacklist(delegate, cb, gocache.New(1*time.Minute, 2*time.Minute), &fakePgBlacklist{})

			for i := 0; i < threshold+2; i++ {
				_, _ = bl.IsBlacklisted(context.Background(), "sess-y")
			}

			if cb.State() != StateClosed {
				t.Fatalf("[%s] expected StateClosed after %d non-infra errors, got %d",
					tc.name, threshold+2, cb.State())
			}
		})
	}
}

// ── L1 cache consulted before PG when circuit is OPEN ─────────────────────────

func TestL1Cache_ConsultedBeforePG_WhenOpen(t *testing.T) {
	cfg := testCfg()
	cb := NewCircuitBreaker(cfg, WithSentryCapture(func(error) {}))
	l1 := gocache.New(1*time.Minute, 2*time.Minute)
	pg := &fakePgBlacklist{entries: map[string]time.Time{"sess-l1": time.Now().Add(5 * time.Minute)}}
	delegate := &erroringBlacklist{err: io.EOF}
	bl := NewResilientBlacklist(delegate, cb, l1, pg)

	// Force circuit OPEN.
	forceOpen(cb)

	// Seed L1 — result should come from here, NOT from PG.
	l1.Set("sess-l1", true, 1*time.Minute)
	delegateBefore := delegate.callCount

	got, err := bl.IsBlacklisted(context.Background(), "sess-l1")
	if err != nil || !got {
		t.Fatalf("expected L1 hit (true, nil): got=%v err=%v", got, err)
	}
	if delegate.callCount != delegateBefore {
		t.Fatal("delegate was called when circuit was OPEN and L1 had the entry")
	}
}

// ── PG fallback activates on L1 miss when OPEN ────────────────────────────────

func TestPGFallback_ActivatesOnL1Miss_WhenOpen(t *testing.T) {
	cfg := testCfg()
	cb := NewCircuitBreaker(cfg, WithSentryCapture(func(error) {}))
	l1 := gocache.New(1*time.Minute, 2*time.Minute)
	pg := &fakePgBlacklist{entries: map[string]time.Time{"sess-pg": time.Now().Add(5 * time.Minute)}}
	delegate := &erroringBlacklist{err: io.EOF}
	bl := NewResilientBlacklist(delegate, cb, l1, pg)

	forceOpen(cb)
	// L1 is empty — must fall through to PG.
	delegateBefore := delegate.callCount

	got, err := bl.IsBlacklisted(context.Background(), "sess-pg")
	if err != nil || !got {
		t.Fatalf("expected PG fallback hit (true, nil): got=%v err=%v", got, err)
	}
	if delegate.callCount != delegateBefore {
		t.Fatal("delegate was called when circuit was OPEN")
	}
	// L1 should now be populated for the next request.
	if _, found := l1.Get("sess-pg"); !found {
		t.Fatal("expected L1 to be populated after PG fallback")
	}
}

// ── context.Canceled specifically does not trip ────────────────────────────────

func TestContextCanceled_DoesNotTripBreaker(t *testing.T) {
	cfg := testCfg()
	cfg.FailureThreshold = 2
	cb := NewCircuitBreaker(cfg, WithSentryCapture(func(error) {}))
	delegate := &erroringBlacklist{err: context.Canceled}
	bl := NewResilientBlacklist(delegate, cb, gocache.New(1*time.Minute, 2*time.Minute), &fakePgBlacklist{})

	for i := 0; i < 5; i++ {
		_, _ = bl.IsBlacklisted(context.Background(), "sess-z")
	}
	if cb.State() != StateClosed {
		t.Fatalf("context.Canceled should not trip breaker; got state %d", cb.State())
	}
}

// ── context.DeadlineExceeded specifically trips ────────────────────────────────

func TestContextDeadlineExceeded_TripsBreaker(t *testing.T) {
	cfg := testCfg()
	cfg.FailureThreshold = 2
	cb := NewCircuitBreaker(cfg, WithSentryCapture(func(error) {}))
	delegate := &erroringBlacklist{err: context.DeadlineExceeded}
	bl := NewResilientBlacklist(delegate, cb, gocache.New(1*time.Minute, 2*time.Minute), &fakePgBlacklist{})

	for i := 0; i < cfg.FailureThreshold; i++ {
		_, _ = bl.IsBlacklisted(context.Background(), "sess-w")
	}
	if cb.State() != StateOpen {
		t.Fatalf("context.DeadlineExceeded should trip breaker; got state %d", cb.State())
	}
}
