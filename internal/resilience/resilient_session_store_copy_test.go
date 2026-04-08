package resilience

import (
	"context"
	"testing"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/session"
)

// TestCopySess_PreservesAllFields verifies that copySess produces a field-equal
// copy and that mutating the copy does not affect the original.
func TestCopySess_PreservesAllFields(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	orig := session.BFFSession{
		SessionID:         "sid-1",
		KratosID:          "kratos-1",
		DeviceID:          "dev-1",
		HydraAccessToken:  "access-tok",
		HydraRefreshToken: "refresh-tok",
		AccessTokenExp:    now.Add(15 * time.Minute),
		CreatedAt:         now,
		ExpiresAt:         now.Add(7 * 24 * time.Hour),
	}

	got := copySess(orig)

	// All fields must match.
	if got != orig {
		t.Fatalf("copySess produced different value:\ngot  %+v\nwant %+v", got, orig)
	}

	// Mutating the copy must not affect the original.
	got.KratosID = "mutated"
	if orig.KratosID == "mutated" {
		t.Fatal("mutating copy changed original — copySess is not producing a copy")
	}
}

// TestResilientSessionStore_Get_L1Hit_ReturnsCopy verifies that a session returned
// from the L1 cache is a copy: mutating the returned value does not alter what is
// stored in L1 on a subsequent Get.
func TestResilientSessionStore_Get_L1Hit_ReturnsCopy(t *testing.T) {
	delegate := &fakeSessionStore{}
	cb := NewCircuitBreaker(testCfg())
	l1 := newL1()
	store := NewResilientSessionStore(delegate, cb, l1)

	orig := newTestSession("copy-s1")
	l1.Set(sessionL1Prefix+"copy-s1", orig, gocache.DefaultExpiration)

	// First Get — should return a copy.
	first, err := store.Get(context.Background(), "copy-s1")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}

	// Mutate the returned copy.
	first.KratosID = "mutated"

	// Second Get — L1 must still hold the original value.
	second, err := store.Get(context.Background(), "copy-s1")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if second.KratosID == "mutated" {
		t.Fatal("L1 cache entry was mutated through the returned pointer — copySess not applied")
	}
	if second.KratosID != orig.KratosID {
		t.Fatalf("second Get returned %q; want %q", second.KratosID, orig.KratosID)
	}
}

// TestResilientSessionStore_GetAllForUser_ReturnsCopies verifies the copy invariant
// on the slice returned by GetAllForUser.
func TestResilientSessionStore_GetAllForUser_ReturnsCopies(t *testing.T) {
	sess := newTestSession("copy-s2")
	delegate := &fakeSessionStore{sessions: map[string]session.BFFSession{"copy-s2": sess}}
	cb := NewCircuitBreaker(testCfg())
	store := NewResilientSessionStore(delegate, cb, newL1())

	sessions, err := store.GetAllForUser(context.Background(), "kratos-1")
	if err != nil || len(sessions) == 0 {
		t.Fatalf("GetAllForUser: err=%v len=%d", err, len(sessions))
	}

	// Mutate the returned element.
	sessions[0].KratosID = "mutated"

	// The delegate's in-memory map should be unaffected.
	delegate.mu.Lock()
	stored := delegate.sessions["copy-s2"]
	delegate.mu.Unlock()
	if stored.KratosID == "mutated" {
		t.Fatal("mutation of returned slice element affected delegate's stored session")
	}
}
