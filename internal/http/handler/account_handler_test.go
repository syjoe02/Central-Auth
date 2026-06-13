package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"central-auth/internal/http/handler"
	"central-auth/internal/model"
	"central-auth/internal/service"

	"github.com/gin-gonic/gin"
)

type mockAccountService struct {
	getMeFn         func(ctx context.Context, sessionID string) (*model.AccountMeResponse, error)
	getSessionsFn   func(ctx context.Context, sessionID string) (*model.SessionsResponse, error)
	logoutDevicesFn func(ctx context.Context, sessionID string, deviceIDs []string) error
	logoutOtherFn   func(ctx context.Context, sessionID string) error
}

func (m *mockAccountService) GetMe(ctx context.Context, sid string) (*model.AccountMeResponse, error) {
	return m.getMeFn(ctx, sid)
}
func (m *mockAccountService) GetSessions(ctx context.Context, sid string) (*model.SessionsResponse, error) {
	return m.getSessionsFn(ctx, sid)
}
func (m *mockAccountService) LogoutDevices(ctx context.Context, sid string, ids []string) error {
	return m.logoutDevicesFn(ctx, sid, ids)
}
func (m *mockAccountService) LogoutOtherDevices(ctx context.Context, sid string) error {
	return m.logoutOtherFn(ctx, sid)
}

var _ service.AccountServiceI = (*mockAccountService)(nil)

func setupAccountRouter(svc service.AccountServiceI) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := handler.NewAccountHandler(svc)
	injectSession := func(c *gin.Context) {
		c.Set("sessionID", "test-session-id")
		c.Next()
	}
	g := r.Group("/bff/account")
	g.Use(injectSession)
	g.GET("/me", h.GetMe)
	g.GET("/sessions", h.GetSessions)

	r.POST("/bff/logout-devices", injectSession, h.LogoutDevices)
	r.POST("/bff/logout-other-devices", injectSession, h.LogoutOtherDevices)
	return r
}

func TestAccountHandler_GetMe_Returns200(t *testing.T) {
	svc := &mockAccountService{
		getMeFn: func(_ context.Context, _ string) (*model.AccountMeResponse, error) {
			return &model.AccountMeResponse{Email: "alice@example.com", Name: "Alice", LoginProvider: "Google"}, nil
		},
	}
	r := setupAccountRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/bff/account/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp model.AccountMeResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Email != "alice@example.com" {
		t.Errorf("email = %q", resp.Email)
	}
}

func TestAccountHandler_GetMe_Returns500OnServiceError(t *testing.T) {
	svc := &mockAccountService{
		getMeFn: func(_ context.Context, _ string) (*model.AccountMeResponse, error) {
			return nil, errors.New("kratos unavailable")
		},
	}
	r := setupAccountRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/bff/account/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestAccountHandler_LogoutDevices_Returns400OnMissingDeviceIds(t *testing.T) {
	svc := &mockAccountService{}
	r := setupAccountRouter(svc)
	// Empty deviceIds array should fail binding validation (min=1).
	body, _ := json.Marshal(map[string]any{"deviceIds": []string{}})
	req := httptest.NewRequest(http.MethodPost, "/bff/logout-devices", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAccountHandler_LogoutDevices_Returns200OnSuccess(t *testing.T) {
	called := false
	svc := &mockAccountService{
		logoutDevicesFn: func(_ context.Context, _ string, ids []string) error {
			called = true
			if len(ids) != 1 || ids[0] != "device-A" {
				t.Errorf("unexpected deviceIDs: %v", ids)
			}
			return nil
		},
	}
	r := setupAccountRouter(svc)
	body, _ := json.Marshal(model.LogoutDevicesRequest{DeviceIDs: []string{"device-A"}})
	req := httptest.NewRequest(http.MethodPost, "/bff/logout-devices", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("LogoutDevices was not called")
	}
}

func TestAccountHandler_GetSessions_Returns200(t *testing.T) {
	now := time.Now()
	svc := &mockAccountService{
		getSessionsFn: func(_ context.Context, _ string) (*model.SessionsResponse, error) {
			return &model.SessionsResponse{
				CurrentDevice: &model.DeviceInfo{
					DeviceID: "d1", Browser: "Chrome 149", OS: "macOS",
					LastUsedAt: &now, IsCurrent: true,
				},
				OtherDevices: []model.DeviceInfo{},
			}, nil
		},
	}
	r := setupAccountRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/bff/account/sessions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
