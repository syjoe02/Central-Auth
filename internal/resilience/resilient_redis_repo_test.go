package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/repository"
)

// ── fake repository.RedisRepo ─────────────────────────────────────────────────

type fakeRedisRepo struct {
	mu     sync.Mutex
	tokens map[string]string // key = "kratosID:deviceID"
}

func (f *fakeRedisRepo) key(kratosID, deviceID string) string {
	return kratosID + ":" + deviceID
}

func (f *fakeRedisRepo) SaveLogin(_ context.Context, kratosID, deviceID, token string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens == nil {
		f.tokens = make(map[string]string)
	}
	f.tokens[f.key(kratosID, deviceID)] = token
	return nil
}

func (f *fakeRedisRepo) GetDeviceRefreshToken(_ context.Context, kratosID, deviceID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[f.key(kratosID, deviceID)]
	if !ok {
		return "", errors.New("not found")
	}
	return t, nil
}

func (f *fakeRedisRepo) RotateRefreshToken(_ context.Context, kratosID, deviceID, newToken string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens == nil {
		f.tokens = make(map[string]string)
	}
	f.tokens[f.key(kratosID, deviceID)] = newToken
	return nil
}

func (f *fakeRedisRepo) LogoutDevice(_ context.Context, kratosID, deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tokens, f.key(kratosID, deviceID))
	return nil
}

func (f *fakeRedisRepo) LogoutAll(_ context.Context, kratosID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k := range f.tokens {
		if len(k) >= len(kratosID) && k[:len(kratosID)] == kratosID {
			delete(f.tokens, k)
		}
	}
	return nil
}

var _ repository.RedisRepo = (*fakeRedisRepo)(nil)

// ── tests ─────────────────────────────────────────────────────────────────────

func TestResilientRedisRepo_GetDeviceRefreshToken_HitsL1(t *testing.T) {
	delegate := &fakeRedisRepo{}
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	repo := NewResilientRedisRepo(delegate, cb, l1)

	// Seed L1 directly.
	l1Key := deviceTokenL1Key("kratos1", "dev1")
	l1.Set(l1Key, "cached-token", gocache.DefaultExpiration)

	got, err := repo.GetDeviceRefreshToken(context.Background(), "kratos1", "dev1")
	if err != nil || got != "cached-token" {
		t.Fatalf("expected L1 hit with cached-token: got=%q err=%v", got, err)
	}
}

func TestResilientRedisRepo_GetDeviceRefreshToken_ErrRedisUnavailable_WhenOpenAndL1Miss(t *testing.T) {
	delegate := &fakeRedisRepo{}
	cb := NewCircuitBreaker(testCfg())
	forceOpen(cb)
	repo := NewResilientRedisRepo(delegate, cb, newL1())

	_, err := repo.GetDeviceRefreshToken(context.Background(), "kratos1", "dev1")
	if !errors.Is(err, ErrRedisUnavailable) {
		t.Fatalf("expected ErrRedisUnavailable when OPEN+L1 miss, got %v", err)
	}
}

func TestResilientRedisRepo_SaveLogin_ErrRedisUnavailable_WhenOpen(t *testing.T) {
	delegate := &fakeRedisRepo{}
	cb := NewCircuitBreaker(testCfg())
	forceOpen(cb)
	repo := NewResilientRedisRepo(delegate, cb, newL1())

	err := repo.SaveLogin(context.Background(), "kratos1", "dev1", "tok", 30*time.Minute)
	if !errors.Is(err, ErrRedisUnavailable) {
		t.Fatalf("expected ErrRedisUnavailable for SaveLogin when OPEN, got %v", err)
	}
}

func TestResilientRedisRepo_SaveLogin_PopulatesL1_WhenClosed(t *testing.T) {
	delegate := &fakeRedisRepo{}
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	repo := NewResilientRedisRepo(delegate, cb, l1)

	if err := repo.SaveLogin(context.Background(), "kratos2", "dev2", "my-token", 30*time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	val, found := l1.Get(deviceTokenL1Key("kratos2", "dev2"))
	if !found {
		t.Fatal("expected L1 populated after SaveLogin")
	}
	if val.(string) != "my-token" {
		t.Fatalf("expected L1 value 'my-token', got %q", val.(string))
	}
}
