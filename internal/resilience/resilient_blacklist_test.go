package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	gocache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"

	"central-auth/internal/blacklist"
	"central-auth/internal/repository"
)

// ── fake PG repository ─────────────────────────────────────────────────────────

type fakePgBlacklist struct {
	mu      sync.Mutex
	entries map[string]time.Time
	readErr error
}

func (f *fakePgBlacklist) IsBlacklisted(_ context.Context, sessionID string) (bool, error) {
	if f.readErr != nil {
		return false, f.readErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.entries[sessionID]
	if !ok {
		return false, nil
	}
	return time.Now().Before(exp), nil
}

func (f *fakePgBlacklist) Add(_ context.Context, sessionID string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.entries == nil {
		f.entries = make(map[string]time.Time)
	}
	existing, ok := f.entries[sessionID]
	if !ok || expiresAt.After(existing) {
		f.entries[sessionID] = expiresAt
	}
	return nil
}

func (f *fakePgBlacklist) DeleteExpired(_ context.Context) error { return nil }

func (f *fakePgBlacklist) ListActive(_ context.Context) ([]repository.BlacklistEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	var out []repository.BlacklistEntry
	for id, exp := range f.entries {
		if exp.After(now) {
			out = append(out, repository.BlacklistEntry{SessionID: id, ExpiresAt: exp})
		}
	}
	return out, nil
}

var _ repository.BlacklistPgRepository = (*fakePgBlacklist)(nil)

// failingPgBlacklist always returns an error for IsBlacklisted.
type failingPgBlacklist struct{}

func (f *failingPgBlacklist) IsBlacklisted(_ context.Context, _ string) (bool, error) {
	return false, errors.New("pg: connection refused")
}
func (f *failingPgBlacklist) Add(_ context.Context, _ string, _ time.Time) error {
	return errors.New("pg: connection refused")
}
func (f *failingPgBlacklist) DeleteExpired(_ context.Context) error { return nil }
func (f *failingPgBlacklist) ListActive(_ context.Context) ([]repository.BlacklistEntry, error) {
	return nil, errors.New("pg: connection refused")
}

// ── helpers ────────────────────────────────────────────────────────────────────

func newMiniredisBlacklist(t *testing.T) (*miniredis.Miniredis, *redis.Client, blacklist.Blacklist) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb, blacklist.NewRedisBlacklist(rdb)
}

func newL1() *gocache.Cache { return gocache.New(1*time.Minute, 2*time.Minute) }

// forceOpen forces the circuit breaker into the OPEN state with a far-future probe time.
func forceOpen(cb CircuitBreaker) {
	c := cb.(*circuitBreaker)
	c.state.Store(int32(StateOpen))
	c.nextProbeAt.Store(time.Now().Add(10 * time.Hour).UnixNano())
}

// ── tests ──────────────────────────────────────────────────────────────────────

func TestResilientBlacklist_IsBlacklisted_HitsRedis_WhenClosed(t *testing.T) {
	_, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	pg := &fakePgBlacklist{}
	bl := NewResilientBlacklist(delegate, cb, newL1(), pg)

	_ = delegate.Add(context.Background(), "sess1", 5*time.Minute)

	got, err := bl.IsBlacklisted(context.Background(), "sess1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected session to be blacklisted")
	}
}

func TestResilientBlacklist_IsBlacklisted_NotBlacklisted(t *testing.T) {
	_, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	bl := NewResilientBlacklist(delegate, cb, newL1(), &fakePgBlacklist{})

	got, err := bl.IsBlacklisted(context.Background(), "unknown")
	if err != nil || got {
		t.Fatalf("unexpected result for unknown session: got=%v err=%v", got, err)
	}
}

func TestResilientBlacklist_IsBlacklisted_HitsL1_WhenOpen(t *testing.T) {
	_, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	forceOpen(cb)
	l1.Set("sess1", true, 1*time.Minute) // seed L1

	bl := NewResilientBlacklist(delegate, cb, l1, &fakePgBlacklist{})
	got, err := bl.IsBlacklisted(context.Background(), "sess1")
	if err != nil || !got {
		t.Fatalf("expected L1 hit: got=%v err=%v", got, err)
	}
}

func TestResilientBlacklist_IsBlacklisted_HitsPG_OnL1Miss(t *testing.T) {
	_, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	forceOpen(cb)
	pg := &fakePgBlacklist{entries: map[string]time.Time{"sess2": time.Now().Add(5 * time.Minute)}}

	bl := NewResilientBlacklist(delegate, cb, l1, pg)
	got, err := bl.IsBlacklisted(context.Background(), "sess2")
	if err != nil || !got {
		t.Fatalf("expected PG fallback hit: got=%v err=%v", got, err)
	}
	if _, found := l1.Get("sess2"); !found {
		t.Fatal("expected L1 to be populated after PG hit")
	}
}

func TestResilientBlacklist_FailClosed_OnPGError(t *testing.T) {
	_, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	forceOpen(cb)

	bl := NewResilientBlacklist(delegate, cb, newL1(), &failingPgBlacklist{})
	got, err := bl.IsBlacklisted(context.Background(), "sessX")
	if err == nil {
		t.Fatal("expected error from PG failure")
	}
	if !got {
		t.Fatal("expected fail-closed (true) on PG error")
	}
}

func TestResilientBlacklist_Add_WritesToRedis_WhenClosed(t *testing.T) {
	mr, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	bl := NewResilientBlacklist(delegate, cb, l1, &fakePgBlacklist{})

	if err := bl.Add(context.Background(), "sess3", 5*time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mr.Exists("bff:blacklist:sess3") {
		t.Fatal("expected key in Redis after Add")
	}
	if _, found := l1.Get("sess3"); !found {
		t.Fatal("expected L1 populated after Add")
	}
}

func TestResilientBlacklist_Add_DualWrite_WhenOpen(t *testing.T) {
	_, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	forceOpen(cb)
	pg := &fakePgBlacklist{}

	bl := NewResilientBlacklist(delegate, cb, l1, pg)
	err := bl.Add(context.Background(), "sess4", 5*time.Minute)
	if !errors.Is(err, ErrRedisUnavailable) {
		t.Fatalf("expected ErrRedisUnavailable, got %v", err)
	}
	pg.mu.Lock()
	_, ok := pg.entries["sess4"]
	pg.mu.Unlock()
	if !ok {
		t.Fatal("expected PG to have entry after dual-write")
	}
	if _, found := l1.Get("sess4"); !found {
		t.Fatal("expected L1 populated after dual-write")
	}
}

func TestResilientBlacklist_AddBatch_DualWrite_WhenOpen(t *testing.T) {
	_, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	forceOpen(cb)
	pg := &fakePgBlacklist{}

	bl := NewResilientBlacklist(delegate, cb, newL1(), pg)
	err := bl.AddBatch(context.Background(), []string{"b1", "b2", "b3"}, 5*time.Minute)
	if !errors.Is(err, ErrRedisUnavailable) {
		t.Fatalf("expected ErrRedisUnavailable, got %v", err)
	}
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for _, id := range []string{"b1", "b2", "b3"} {
		if _, ok := pg.entries[id]; !ok {
			t.Fatalf("expected PG entry for %s after AddBatch", id)
		}
	}
}

func TestResilientBlacklist_InfraError_TripsBreaker(t *testing.T) {
	mr, _, delegate := newMiniredisBlacklist(t)
	cb := NewCircuitBreaker(testCfg())
	bl := NewResilientBlacklist(delegate, cb, newL1(), &fakePgBlacklist{})

	// Close miniredis to force connection errors.
	mr.Close()

	// 5 calls should trip the circuit.
	for i := 0; i < 5; i++ {
		_, _ = bl.IsBlacklisted(context.Background(), "sess")
	}
	if cb.State() != StateOpen {
		t.Fatalf("expected circuit OPEN after 5 infra errors, got %d", cb.State())
	}
}
