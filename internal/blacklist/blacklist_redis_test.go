package blacklist_test

import (
	"context"
	"testing"
	"time"

	"central-auth/internal/blacklist"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisBlacklist(t *testing.T) (*blacklist.RedisBlacklist, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return blacklist.NewRedisBlacklist(rdb), mr
}

func TestRedisBlacklist_Add_WritesWithTTL(t *testing.T) {
	bl, mr := newTestRedisBlacklist(t)

	if err := bl.Add(context.Background(), "sess1", 5*time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mr.Exists("bff:blacklist:sess1") {
		t.Error("expected key to exist in Redis")
	}
	ttl := mr.TTL("bff:blacklist:sess1")
	if ttl <= 0 || ttl > 5*time.Minute {
		t.Errorf("expected TTL ~5m, got %v", ttl)
	}
}

func TestRedisBlacklist_Add_UsesMinTTLForNonPositive(t *testing.T) {
	// Security fix F-7: non-positive TTLs write with minBlacklistTTL (60s)
	// to guard against in-flight requests during clock skew / session expiry.
	bl, mr := newTestRedisBlacklist(t)

	bl.Add(context.Background(), "sess2", 0)
	bl.Add(context.Background(), "sess3", -time.Second)

	for _, key := range []string{"bff:blacklist:sess2", "bff:blacklist:sess3"} {
		if !mr.Exists(key) {
			t.Errorf("key %s should exist with minBlacklistTTL for non-positive TTL", key)
		}
		ttl := mr.TTL(key)
		if ttl <= 0 || ttl > 60*time.Second {
			t.Errorf("expected TTL ~60s for %s, got %v", key, ttl)
		}
	}
}

func TestRedisBlacklist_IsBlacklisted_TrueForPresent(t *testing.T) {
	bl, mr := newTestRedisBlacklist(t)
	mr.Set("bff:blacklist:sess4", "1")
	mr.SetTTL("bff:blacklist:sess4", 5*time.Minute)

	ok, err := bl.IsBlacklisted(context.Background(), "sess4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected blacklisted=true")
	}
}

func TestRedisBlacklist_IsBlacklisted_FalseForAbsent(t *testing.T) {
	bl, _ := newTestRedisBlacklist(t)

	ok, err := bl.IsBlacklisted(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected blacklisted=false for unknown session")
	}
}

func TestRedisBlacklist_IsBlacklisted_FalseAfterExpiry(t *testing.T) {
	bl, mr := newTestRedisBlacklist(t)

	bl.Add(context.Background(), "sess5", 1*time.Second)
	mr.FastForward(2 * time.Second)

	ok, err := bl.IsBlacklisted(context.Background(), "sess5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected blacklisted=false after TTL expiry")
	}
}

func TestRedisBlacklist_AddBatch_WritesAll(t *testing.T) {
	bl, mr := newTestRedisBlacklist(t)

	ids := []string{"b1", "b2", "b3"}
	if err := bl.AddBatch(context.Background(), ids, 3*time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, id := range ids {
		key := "bff:blacklist:" + id
		if !mr.Exists(key) {
			t.Errorf("expected key %s to exist", key)
		}
		ttl := mr.TTL(key)
		if ttl <= 0 || ttl > 3*time.Minute {
			t.Errorf("unexpected TTL for %s: %v", key, ttl)
		}
	}
}

func TestRedisBlacklist_AddBatch_NoOpOnEmpty(t *testing.T) {
	bl, _ := newTestRedisBlacklist(t)

	if err := bl.AddBatch(context.Background(), nil, time.Minute); err != nil {
		t.Fatalf("unexpected error on nil: %v", err)
	}
	if err := bl.AddBatch(context.Background(), []string{}, time.Minute); err != nil {
		t.Fatalf("unexpected error on empty slice: %v", err)
	}
}
