package blacklist_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"central-auth/internal/blacklist"
)

// ── in-memory stub ────────────────────────────────────────────────────────────

// stubBlacklist is an in-memory blacklist used to test the interface contract
// independently of Redis. Tests for the RedisBlacklist itself rely on an
// integration test with a real Redis instance.
type stubBlacklist struct {
	entries map[string]bool
	addErr  error
	getErr  error
}

func newStub() *stubBlacklist { return &stubBlacklist{entries: make(map[string]bool)} }

func (s *stubBlacklist) Add(_ context.Context, id string, ttl time.Duration) error {
	if s.addErr != nil {
		return s.addErr
	}
	if ttl > 0 {
		s.entries[id] = true
	}
	return nil
}

func (s *stubBlacklist) IsBlacklisted(_ context.Context, id string) (bool, error) {
	if s.getErr != nil {
		return true, s.getErr // fail-closed
	}
	return s.entries[id], nil
}

func (s *stubBlacklist) AddBatch(_ context.Context, ids []string, ttl time.Duration) error {
	if s.addErr != nil {
		return s.addErr
	}
	if ttl <= 0 {
		return nil
	}
	for _, id := range ids {
		s.entries[id] = true
	}
	return nil
}

var _ blacklist.Blacklist = (*stubBlacklist)(nil)

// ── interface contract tests ───────────────────────────────────────────────────

func TestBlacklist_Add_StoresEntry(t *testing.T) {
	bl := newStub()
	if err := bl.Add(context.Background(), "sess1", time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ok, _ := bl.IsBlacklisted(context.Background(), "sess1")
	if !ok {
		t.Error("expected session to be blacklisted after Add")
	}
}

func TestBlacklist_Add_SkipsNonPositiveTTL(t *testing.T) {
	bl := newStub()
	bl.Add(context.Background(), "sess2", 0)
	bl.Add(context.Background(), "sess3", -time.Second)

	for _, id := range []string{"sess2", "sess3"} {
		ok, _ := bl.IsBlacklisted(context.Background(), id)
		if ok {
			t.Errorf("session %s should not be blacklisted with TTL <= 0", id)
		}
	}
}

func TestBlacklist_IsBlacklisted_ReturnsFalseForUnknown(t *testing.T) {
	bl := newStub()
	ok, err := bl.IsBlacklisted(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false for unknown session")
	}
}

func TestBlacklist_FailClosed_OnError(t *testing.T) {
	bl := newStub()
	bl.getErr = fmt.Errorf("redis down")

	ok, err := bl.IsBlacklisted(context.Background(), "any")
	if err == nil {
		t.Fatal("expected error on backend failure")
	}
	if !ok {
		t.Error("expected fail-closed (true) when backend returns error")
	}
}

func TestBlacklist_AddBatch_BlacklistsAll(t *testing.T) {
	bl := newStub()
	ids := []string{"s1", "s2", "s3"}
	if err := bl.AddBatch(context.Background(), ids, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, id := range ids {
		ok, _ := bl.IsBlacklisted(context.Background(), id)
		if !ok {
			t.Errorf("session %s not blacklisted after AddBatch", id)
		}
	}
}

func TestBlacklist_AddBatch_NoOpOnEmpty(t *testing.T) {
	bl := newStub()
	if err := bl.AddBatch(context.Background(), nil, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := bl.AddBatch(context.Background(), []string{}, time.Minute); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBlacklist_AddBatch_NoOpOnZeroTTL(t *testing.T) {
	bl := newStub()
	bl.AddBatch(context.Background(), []string{"s1", "s2"}, 0)

	for _, id := range []string{"s1", "s2"} {
		ok, _ := bl.IsBlacklisted(context.Background(), id)
		if ok {
			t.Errorf("session %s should not be blacklisted with TTL=0", id)
		}
	}
}
