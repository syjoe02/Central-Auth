package requestid_test

import (
	"context"
	"testing"

	"central-auth/internal/requestid"
)

func TestWithRequestID_StoresValue(t *testing.T) {
	ctx := requestid.WithRequestID(context.Background(), "req-abc123")
	got := requestid.FromContext(ctx)
	if got != "req-abc123" {
		t.Fatalf("FromContext = %q; want %q", got, "req-abc123")
	}
}

func TestFromContext_EmptyString_WhenKeyAbsent(t *testing.T) {
	got := requestid.FromContext(context.Background())
	if got != "" {
		t.Fatalf("FromContext on plain context = %q; want %q", got, "")
	}
}

func TestFromContext_ChildContext_InheritsID(t *testing.T) {
	parent := requestid.WithRequestID(context.Background(), "parent-id")
	child, cancel := context.WithCancel(parent)
	defer cancel()
	got := requestid.FromContext(child)
	if got != "parent-id" {
		t.Fatalf("child context FromContext = %q; want %q", got, "parent-id")
	}
}
