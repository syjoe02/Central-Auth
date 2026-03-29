package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"central-auth/internal/session"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*session.RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return session.NewRedisStore(rdb, 7*24*time.Hour), mr
}

func testSession(id, kratosID string) session.BFFSession {
	now := time.Now()
	return session.BFFSession{
		SessionID:         id,
		KratosID:          kratosID,
		DeviceID:          "dev1",
		HydraAccessToken:  "at-" + id,
		HydraRefreshToken: "rt-" + id,
		AccessTokenExp:    now.Add(15 * time.Minute),
		CreatedAt:         now,
		ExpiresAt:         now.Add(7 * 24 * time.Hour),
	}
}

func TestStore_CreateAndGet_RoundTrip(t *testing.T) {
	store, _ := newTestStore(t)
	sess := testSession("sess1", "kratos1")

	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(context.Background(), "sess1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.KratosID != "kratos1" {
		t.Errorf("expected KratosID=kratos1, got %q", got.KratosID)
	}
	if got.HydraAccessToken != "at-sess1" {
		t.Errorf("expected HydraAccessToken=at-sess1, got %q", got.HydraAccessToken)
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	store, _ := newTestStore(t)

	_, err := store.Get(context.Background(), "nonexistent")
	if !errors.Is(err, session.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestStore_Create_SetsUserIndex(t *testing.T) {
	store, mr := newTestStore(t)
	sess := testSession("sess2", "kratos2")

	store.Create(context.Background(), sess)

	// User index should contain the sessionID.
	members, _ := mr.SMembers("bff:user_sessions:kratos2")
	if len(members) != 1 || members[0] != "sess2" {
		t.Errorf("user index not populated correctly: %v", members)
	}
}

func TestStore_Update_ChangesTokens(t *testing.T) {
	store, _ := newTestStore(t)
	sess := testSession("sess3", "kratos3")
	store.Create(context.Background(), sess)

	sess.HydraAccessToken = "new-at"
	if err := store.Update(context.Background(), sess); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := store.Get(context.Background(), "sess3")
	if got.HydraAccessToken != "new-at" {
		t.Errorf("expected new-at, got %q", got.HydraAccessToken)
	}
}

func TestStore_Delete_RemovesSessionAndIndex(t *testing.T) {
	store, _ := newTestStore(t)
	sess := testSession("sess4", "kratos4")
	store.Create(context.Background(), sess)

	if err := store.Delete(context.Background(), "sess4"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.Get(context.Background(), "sess4")
	if !errors.Is(err, session.ErrNotFound) {
		t.Error("expected ErrNotFound after Delete")
	}
}

func TestStore_Delete_Idempotent(t *testing.T) {
	store, _ := newTestStore(t)
	// Delete of non-existent session should not error.
	if err := store.Delete(context.Background(), "ghost"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStore_GetAllForUser_ReturnsActiveSessions(t *testing.T) {
	store, _ := newTestStore(t)
	store.Create(context.Background(), testSession("s1", "multi-user"))
	store.Create(context.Background(), testSession("s2", "multi-user"))
	store.Create(context.Background(), testSession("s3", "other-user"))

	sessions, err := store.GetAllForUser(context.Background(), "multi-user")
	if err != nil {
		t.Fatalf("GetAllForUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestStore_GetAllForUser_SkipsExpiredSessions(t *testing.T) {
	store, mr := newTestStore(t)
	store.Create(context.Background(), testSession("expired-sess", "exp-user"))

	// Fast-forward past the session TTL.
	mr.FastForward(8 * 24 * time.Hour)

	sessions, err := store.GetAllForUser(context.Background(), "exp-user")
	if err != nil {
		t.Fatalf("GetAllForUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 live sessions after expiry, got %d", len(sessions))
	}
}

func TestStore_DeleteAllForUser_ReturnsDeletedIDs(t *testing.T) {
	store, _ := newTestStore(t)
	store.Create(context.Background(), testSession("da1", "del-user"))
	store.Create(context.Background(), testSession("da2", "del-user"))

	deleted, err := store.DeleteAllForUser(context.Background(), "del-user")
	if err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}
	if len(deleted) != 2 {
		t.Errorf("expected 2 deleted IDs, got %d", len(deleted))
	}

	// Verify sessions are gone.
	for _, id := range []string{"da1", "da2"} {
		if _, err := store.Get(context.Background(), id); !errors.Is(err, session.ErrNotFound) {
			t.Errorf("session %s should be deleted", id)
		}
	}
}

func TestStore_AcquireRefreshLock_ExclusiveAccess(t *testing.T) {
	store, _ := newTestStore(t)

	// First acquisition should succeed.
	ok1, err := store.AcquireRefreshLock(context.Background(), "lock-sess", 5*time.Second)
	if err != nil || !ok1 {
		t.Fatalf("first lock acquisition failed: ok=%v err=%v", ok1, err)
	}

	// Second acquisition should fail (lock held).
	ok2, err := store.AcquireRefreshLock(context.Background(), "lock-sess", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error on second attempt: %v", err)
	}
	if ok2 {
		t.Error("second lock acquisition should fail while lock is held")
	}
}

func TestStore_ReleaseRefreshLock_AllowsReacquisition(t *testing.T) {
	store, _ := newTestStore(t)

	store.AcquireRefreshLock(context.Background(), "rel-sess", 30*time.Second)
	store.ReleaseRefreshLock(context.Background(), "rel-sess")

	ok, err := store.AcquireRefreshLock(context.Background(), "rel-sess", 5*time.Second)
	if err != nil || !ok {
		t.Errorf("expected lock reacquisition after release: ok=%v err=%v", ok, err)
	}
}
