package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"central-auth/internal/config"
	"central-auth/internal/http/handler"
	"central-auth/internal/service"

	"github.com/gin-gonic/gin"
)

// ── mock BFF service ──────────────────────────────────────────────────────────

type mockBFFService struct {
	loginFn          func(ctx context.Context, kratosID, deviceID string, rememberMe bool, kratosToken string, ua, ip *string) (string, error)
	logoutFn         func(ctx context.Context, sessionID string) error
	logoutAllFn      func(ctx context.Context, sessionID string) error
	resolveSessionFn func(ctx context.Context, sessionID string) (string, string, string, error)
	whoAmIFn         func(ctx context.Context, sessionID string) (string, string, error)
}

func (m *mockBFFService) Login(ctx context.Context, k, d string, r bool, kt string, ua, ip *string) (string, error) {
	return m.loginFn(ctx, k, d, r, kt, ua, ip)
}
func (m *mockBFFService) Logout(ctx context.Context, id string) error    { return m.logoutFn(ctx, id) }
func (m *mockBFFService) LogoutAll(ctx context.Context, id string) error { return m.logoutAllFn(ctx, id) }
func (m *mockBFFService) ResolveSession(ctx context.Context, id string) (string, string, string, error) {
	return m.resolveSessionFn(ctx, id)
}
func (m *mockBFFService) WhoAmI(ctx context.Context, id string) (string, string, error) {
	return m.whoAmIFn(ctx, id)
}

var _ service.BFFServiceI = (*mockBFFService)(nil)

// ── helpers ───────────────────────────────────────────────────────────────────

func testBFFCfg() config.BFFConfig {
	return config.BFFConfig{
		CookieDomain: "example.com",
		CookieSecure: false, // false so httptest works without TLS
		SessionTTL:   7 * 24 * time.Hour,
		CSRFSecret:   "testsecret",
	}
}

func setupRouter(svc service.BFFServiceI) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := handler.NewBFFHandler(svc, testBFFCfg())
	r.POST("/bff/login", h.Login)

	// For protected routes inject sessionID manually (bypassing middleware in unit tests).
	protected := r.Group("/bff")
	protected.Use(func(c *gin.Context) {
		c.Set("sessionID", "test-session-id")
		c.Next()
	})
	protected.POST("/logout", h.Logout)
	protected.POST("/logout-all", h.LogoutAll)
	protected.GET("/whoami", h.WhoAmI)
	return r
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestLogin_SetsCookieOnSuccess(t *testing.T) {
	svc := &mockBFFService{
		loginFn: func(_ context.Context, _, _ string, _ bool, _ string, _, _ *string) (string, error) {
			return strings.Repeat("a", 64), nil
		},
	}
	r := setupRouter(svc)

	body, _ := json.Marshal(map[string]interface{}{
		"user_id":   "kratos1",
		"device_id": "dev1",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bff/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "__session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("__session cookie not set")
	}
	if !sessionCookie.HttpOnly {
		t.Error("__session cookie must be HttpOnly")
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Error("__session cookie must be SameSite=Strict")
	}

	// Tokens must NOT appear in the response body.
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["access_token"]; ok {
		t.Error("access_token must not be in response body")
	}
	if _, ok := resp["refresh_token"]; ok {
		t.Error("refresh_token must not be in response body")
	}
}

func TestLogin_Returns400_OnMissingFields(t *testing.T) {
	svc := &mockBFFService{}
	r := setupRouter(svc)

	body, _ := json.Marshal(map[string]interface{}{}) // missing required fields
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bff/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestLogin_Returns500_OnServiceError(t *testing.T) {
	svc := &mockBFFService{
		loginFn: func(_ context.Context, _, _ string, _ bool, _ string, _, _ *string) (string, error) {
			return "", errors.New("internal error")
		},
	}
	r := setupRouter(svc)

	body, _ := json.Marshal(map[string]interface{}{"user_id": "k1", "device_id": "d1"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bff/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	// Error message must not expose internals.
	if strings.Contains(w.Body.String(), "internal error") {
		t.Error("internal error details must not be exposed to browser")
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	svc := &mockBFFService{
		logoutFn: func(_ context.Context, _ string) error { return nil },
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bff/logout", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "__session" && c.MaxAge == -1 {
			return // cookie cleared
		}
	}
	t.Error("expected __session cookie to be cleared (MaxAge=-1)")
}

func TestWhoAmI_Returns401_OnBlacklistedSession(t *testing.T) {
	svc := &mockBFFService{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "", "", service.ErrSessionBlacklisted
		},
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bff/whoami", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestWhoAmI_ReturnsKratosAndDeviceID(t *testing.T) {
	svc := &mockBFFService{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "kratos1", "device1", nil
		},
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bff/whoami", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["kratos_id"] != "kratos1" {
		t.Errorf("expected kratos_id=kratos1, got %q", resp["kratos_id"])
	}
	// hydra tokens must not appear
	if _, ok := resp["hydra_access_token"]; ok {
		t.Error("hydra_access_token must not appear in whoami response")
	}
}

func TestLogoutAll_ClearsCookieAndReturnsOK(t *testing.T) {
	svc := &mockBFFService{
		logoutAllFn: func(_ context.Context, _ string) error { return nil },
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bff/logout-all", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "__session" && c.MaxAge == -1 {
			return
		}
	}
	t.Error("expected __session cookie to be cleared")
}

func TestLogoutAll_Returns500_OnServiceError(t *testing.T) {
	svc := &mockBFFService{
		logoutAllFn: func(_ context.Context, _ string) error { return errors.New("fail") },
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bff/logout-all", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestLogout_Returns500_OnServiceError(t *testing.T) {
	svc := &mockBFFService{
		logoutFn: func(_ context.Context, _ string) error { return errors.New("fail") },
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bff/logout", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestWhoAmI_Returns500_OnInternalError(t *testing.T) {
	svc := &mockBFFService{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "", "", errors.New("database unavailable")
		},
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bff/whoami", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestWhoAmI_Returns401_OnSessionNotFound(t *testing.T) {
	svc := &mockBFFService{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "", "", service.ErrSessionNotFound
		},
	}
	r := setupRouter(svc)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bff/whoami", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
