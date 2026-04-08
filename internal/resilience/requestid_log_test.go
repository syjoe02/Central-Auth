package resilience

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"central-auth/internal/requestid"
)

// captureLog redirects the standard logger to a buffer for the duration of the
// test. It restores the original output in a cleanup function.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return buf
}

// TestResilientBlacklist_IsBlacklisted_PGFallback_LogsRequestID verifies that the
// request ID from context appears in log lines emitted during PG fallback.
func TestResilientBlacklist_IsBlacklisted_PGFallback_LogsRequestID(t *testing.T) {
	buf := captureLog(t)

	cb := NewCircuitBreaker(testCfg(), WithSentryCapture(func(error) {}))
	forceOpen(cb)

	pg := &fakePgBlacklist{entries: map[string]time.Time{"sess-log": time.Now().Add(5 * time.Minute)}}
	bl := NewResilientBlacklist(&erroringBlacklist{err: io.EOF}, cb, gocache.New(1*time.Minute, 2*time.Minute), pg)

	rid := "test-req-id-123"
	ctx := requestid.WithRequestID(context.Background(), rid)

	_, _ = bl.IsBlacklisted(ctx, "sess-log")

	if !strings.Contains(buf.String(), rid) {
		t.Fatalf("expected request ID %q in log output; got:\n%s", rid, buf.String())
	}
}

// TestResilientBlacklist_Add_PGFallback_LogsRequestID verifies the OPEN-path Add logs include request ID.
func TestResilientBlacklist_Add_PGFallback_LogsRequestID(t *testing.T) {
	buf := captureLog(t)

	cb := NewCircuitBreaker(testCfg(), WithSentryCapture(func(error) {}))
	forceOpen(cb)

	pg := &fakePgBlacklist{}
	bl := NewResilientBlacklist(&erroringBlacklist{err: io.EOF}, cb, gocache.New(1*time.Minute, 2*time.Minute), pg)

	rid := "add-req-id-456"
	ctx := requestid.WithRequestID(context.Background(), rid)

	_ = bl.Add(ctx, "sess-add", 5*time.Minute)

	if !strings.Contains(buf.String(), rid) {
		t.Fatalf("expected request ID %q in log output; got:\n%s", rid, buf.String())
	}
}

// TestResilientSessionStore_Get_InfraError_LogsRequestID verifies the session store
// logs the request ID when an infra error triggers a RecordFailure.
func TestResilientSessionStore_Get_InfraError_LogsRequestID(t *testing.T) {
	buf := captureLog(t)

	cb := NewCircuitBreaker(testCfg(), WithSentryCapture(func(error) {}))
	delegate := &fakeSessionStore{readErr: io.EOF}
	store := NewResilientSessionStore(delegate, cb, gocache.New(1*time.Minute, 2*time.Minute))

	rid := "sess-req-id-789"
	ctx := requestid.WithRequestID(context.Background(), rid)

	_, _ = store.Get(ctx, "sess-infra")

	if !strings.Contains(buf.String(), rid) {
		t.Fatalf("expected request ID %q in session store log; got:\n%s", rid, buf.String())
	}
}
