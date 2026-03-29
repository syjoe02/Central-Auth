package hydra_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"central-auth/internal/hydra"
)

// TestIntrospectToken_Active verifies that IntrospectToken returns an active result
// and correctly extracts the subject and ext claims.
func TestIntrospectToken_Active(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/oauth2/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true,
			"sub":    "kratos-id-1",
			"ext":    map[string]string{"device_id": "device-1"},
		})
	}))
	defer srv.Close()

	client := hydra.New("http://unused", srv.URL, "client-id", "client-secret", "http://callback")
	result, err := client.IntrospectToken(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Active {
		t.Error("expected active=true")
	}
	if result.Subject != "kratos-id-1" {
		t.Errorf("expected subject=kratos-id-1, got %q", result.Subject)
	}
	if result.DeviceID() != "device-1" {
		t.Errorf("expected device_id=device-1, got %q", result.DeviceID())
	}
}

// TestIntrospectToken_Inactive verifies that an inactive token is correctly reported.
func TestIntrospectToken_Inactive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
	}))
	defer srv.Close()

	client := hydra.New("http://unused", srv.URL, "cid", "csec", "http://cb")
	result, err := client.IntrospectToken(context.Background(), "expired-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Active {
		t.Error("expected active=false for expired token")
	}
}

// TestIntrospectToken_ServerError verifies that a non-200 response returns an error.
func TestIntrospectToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := hydra.New("http://unused", srv.URL, "cid", "csec", "http://cb")
	_, err := client.IntrospectToken(context.Background(), "token")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// TestRevokeToken_Success verifies that a successful revocation returns no error.
func TestRevokeToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/revoke" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := hydra.New(srv.URL, "http://unused-admin", "cid", "csec", "http://cb")
	if err := client.RevokeToken(context.Background(), "some-token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRevokeToken_ServerError verifies that a non-200 from revocation returns an error.
func TestRevokeToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	client := hydra.New(srv.URL, "http://unused-admin", "cid", "csec", "http://cb")
	if err := client.RevokeToken(context.Background(), "token"); err == nil {
		t.Fatal("expected error for non-200 revoke response")
	}
}

// TestRevokeAllForSubject_Success verifies bulk revocation returns no error on 204.
func TestRevokeAllForSubject_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := hydra.New("http://unused", srv.URL, "cid", "csec", "http://cb")
	if err := client.RevokeAllForSubject(context.Background(), "kratos-id-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
