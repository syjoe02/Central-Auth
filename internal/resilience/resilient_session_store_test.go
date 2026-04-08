package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/session"
)

// ── fake session.Store ────────────────────────────────────────────────────────

type fakeSessionStore struct {
	mu       sync.Mutex
	sessions map[string]session.BFFSession
	readErr  error
}

func (f *fakeSessionStore) Create(_ context.Context, s session.BFFSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessions == nil {
		f.sessions = make(map[string]session.BFFSession)
	}
	f.sessions[s.SessionID] = s
	return nil
}

func (f *fakeSessionStore) Get(_ context.Context, sessionID string) (session.BFFSession, error) {
	if f.readErr != nil {
		return session.BFFSession{}, f.readErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok {
		return session.BFFSession{}, session.ErrNotFound
	}
	return s, nil
}

func (f *fakeSessionStore) Update(_ context.Context, s session.BFFSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[s.SessionID] = s
	return nil
}

func (f *fakeSessionStore) Delete(_ context.Context, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, sessionID)
	return nil
}

func (f *fakeSessionStore) GetAllForUser(_ context.Context, kratosID string) ([]session.BFFSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []session.BFFSession
	for _, s := range f.sessions {
		if s.KratosID == kratosID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeSessionStore) DeleteAllForUser(_ context.Context, kratosID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for id, s := range f.sessions {
		if s.KratosID == kratosID {
			ids = append(ids, id)
			delete(f.sessions, id)
		}
	}
	return ids, nil
}

func (f *fakeSessionStore) AcquireRefreshLock(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return true, nil
}

func (f *fakeSessionStore) ReleaseRefreshLock(_ context.Context, _ string) error { return nil }

var _ session.Store = (*fakeSessionStore)(nil)

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestSession(id string) session.BFFSession {
	return session.BFFSession{
		SessionID: id,
		KratosID:  "kratos-1",
		DeviceID:  "device-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestResilientSessionStore_Get_HitsL1_BeforeDelegate(t *testing.T) {
	delegate := &fakeSessionStore{}
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	store := NewResilientSessionStore(delegate, cb, l1)

	sess := newTestSession("s1")
	l1.Set(sessionL1Prefix+"s1", sess, gocache.DefaultExpiration)

	got, err := store.Get(context.Background(), "s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SessionID != "s1" {
		t.Fatalf("expected session s1 from L1, got %q", got.SessionID)
	}
}

func TestResilientSessionStore_Get_PopulatesL1_OnDelegateMiss(t *testing.T) {
	sess := newTestSession("s2")
	delegate := &fakeSessionStore{sessions: map[string]session.BFFSession{"s2": sess}}
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	store := NewResilientSessionStore(delegate, cb, l1)

	got, err := store.Get(context.Background(), "s2")
	if err != nil || got.SessionID != "s2" {
		t.Fatalf("expected s2 from delegate: got=%v err=%v", got, err)
	}
	if _, found := l1.Get(sessionL1Prefix + "s2"); !found {
		t.Fatal("expected L1 to be populated after delegate hit")
	}
}

func TestResilientSessionStore_Get_ErrNotFound_WhenOpenAndL1Miss(t *testing.T) {
	delegate := &fakeSessionStore{}
	cb := NewCircuitBreaker(testCfg())
	forceOpen(cb)
	store := NewResilientSessionStore(delegate, cb, newL1())

	_, err := store.Get(context.Background(), "unknown")
	if !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expected ErrNotFound when OPEN+L1 miss, got %v", err)
	}
}

func TestResilientSessionStore_Create_PopulatesL1(t *testing.T) {
	delegate := &fakeSessionStore{}
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	store := NewResilientSessionStore(delegate, cb, l1)

	sess := newTestSession("s3")
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, found := l1.Get(sessionL1Prefix + "s3"); !found {
		t.Fatal("expected L1 populated after Create")
	}
}

func TestResilientSessionStore_Create_ErrRedisUnavailable_WhenOpen(t *testing.T) {
	delegate := &fakeSessionStore{}
	cb := NewCircuitBreaker(testCfg())
	forceOpen(cb)
	store := NewResilientSessionStore(delegate, cb, newL1())

	err := store.Create(context.Background(), newTestSession("s4"))
	if !errors.Is(err, ErrRedisUnavailable) {
		t.Fatalf("expected ErrRedisUnavailable when OPEN, got %v", err)
	}
}

func TestResilientSessionStore_Delete_EvictsL1_BeforeCBCheck(t *testing.T) {
	delegate := &fakeSessionStore{}
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	forceOpen(cb)

	l1.Set(sessionL1Prefix+"s5", newTestSession("s5"), gocache.DefaultExpiration)
	store := NewResilientSessionStore(delegate, cb, l1)

	// Even when OPEN, L1 must be evicted.
	_ = store.Delete(context.Background(), "s5")
	if _, found := l1.Get(sessionL1Prefix + "s5"); found {
		t.Fatal("expected L1 evicted after Delete even when OPEN")
	}
}

func TestResilientSessionStore_AcquireRefreshLock_ReturnsFalse_WhenOpen(t *testing.T) {
	delegate := &fakeSessionStore{}
	cb := NewCircuitBreaker(testCfg())
	forceOpen(cb)
	store := NewResilientSessionStore(delegate, cb, newL1())

	acquired, err := store.AcquireRefreshLock(context.Background(), "s6", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acquired {
		t.Fatal("expected AcquireRefreshLock to return false when OPEN")
	}
}
