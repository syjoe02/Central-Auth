package kratos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"central-auth/internal/kratos"
)

func TestGetIdentityFull_ParsesTraitsAndCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/identities/abc-123" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":     "abc-123",
			"traits": map[string]any{"email": "user@example.com", "name": map[string]any{"first": "Alice"}},
			"credentials": map[string]any{
				"oidc": map[string]any{"type": "oidc"},
			},
		})
	}))
	defer srv.Close()

	c := kratos.New(srv.URL, srv.URL)
	identity, err := c.GetIdentityFull(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "abc-123" {
		t.Errorf("ID = %q, want abc-123", identity.ID)
	}
	if _, ok := identity.Credentials["oidc"]; !ok {
		t.Error("expected credentials.oidc to be present")
	}
	if _, ok := identity.Credentials["password"]; ok {
		t.Error("expected credentials.password to be absent")
	}
}

func TestGetIdentityFull_ErrorPaths(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
		wantErrSub string
	}{
		{"not found", http.StatusNotFound, `{}`, "not found"},
		{"server error", http.StatusInternalServerError, `{}`, "unexpected status 500"},
		{"bad json", http.StatusOK, `{invalid`, "decode identity-full"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			c := kratos.New(srv.URL, srv.URL)
			_, err := c.GetIdentityFull(context.Background(), "abc-123")
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("want error containing %q, got %v", tc.wantErrSub, err)
			}
		})
	}
}
