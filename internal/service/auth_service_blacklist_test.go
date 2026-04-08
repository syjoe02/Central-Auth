package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"central-auth/internal/blacklist"
	"central-auth/internal/domain"
	"central-auth/internal/hydra"
	"central-auth/internal/resilience"
	"central-auth/internal/service"
)

// ── configurable blacklist mock ───────────────────────────────────────────────
// Named distinctly from bff_service_test.go's mockBlacklist to avoid redeclaration.

type controllableBlacklist struct {
	isBlacklistedFunc func(ctx context.Context, key string) (bool, error)
	addKeys           []string
	addErr            error
}

func (m *controllableBlacklist) IsBlacklisted(ctx context.Context, key string) (bool, error) {
	if m.isBlacklistedFunc != nil {
		return m.isBlacklistedFunc(ctx, key)
	}
	return false, nil
}

func (m *controllableBlacklist) Add(_ context.Context, key string, _ time.Duration) error {
	m.addKeys = append(m.addKeys, key)
	return m.addErr
}

func (m *controllableBlacklist) AddBatch(_ context.Context, keys []string, _ time.Duration) error {
	m.addKeys = append(m.addKeys, keys...)
	return m.addErr
}

var _ blacklist.Blacklist = (*controllableBlacklist)(nil)

// ── helpers ───────────────────────────────────────────────────────────────────

// validClaims returns an AccessTokenClaims with the given kratosID and deviceID.
func validClaims(kratosID, deviceID string) *hydra.AccessTokenClaims {
	return &hydra.AccessTokenClaims{
		Subject:          kratosID,
		Ext:              map[string]interface{}{"device_id": deviceID},
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute))},
	}
}

// validIntrospect returns an active IntrospectResult with the given kratosID and deviceID.
func validIntrospect(kratosID, deviceID string) *hydra.IntrospectResult {
	return &hydra.IntrospectResult{
		Active:  true,
		Subject: kratosID,
		Ext:     map[string]interface{}{"device_id": deviceID},
	}
}

// blSvc constructs an OryAuthService with a controlled Hydra client and
// optional blacklist, using noops for Redis and device-session repos.
func blSvc(bl blacklist.Blacklist) *service.OryAuthService {
	opts := []service.OryAuthServiceOption{}
	if bl != nil {
		opts = append(opts, service.WithBlacklist(bl))
	}
	return service.NewOryAuthService(
		&mockHydraClient{
			validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
				return validClaims("kratos-1", "dev-1"), nil
			},
			introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
				return validIntrospect("kratos-1", "dev-1"), nil
			},
			revokeTokenFunc:  func(_ context.Context, _ string) error { return nil },
			revokeAllFunc:    func(_ context.Context, _ string) error { return nil },
			issueTokensFunc:  func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) { return nil, errors.New("not used") },
			refreshTokenFunc: func(_ context.Context, _ string) (*hydra.TokenSet, error) { return nil, errors.New("not used") },
		},
		&mockRedisRepo{
			saveLoginFunc:          func(_ context.Context, _, _, _ string, _ time.Duration) error { return nil },
			getDeviceRefreshFunc:   func(_ context.Context, _, _ string) (string, error) { return "", nil },
			rotateRefreshTokenFunc: func(_ context.Context, _, _, _ string, _ time.Duration) error { return nil },
			logoutDeviceFunc:       func(_ context.Context, _, _ string) error { return nil },
			logoutAllFunc:          func(_ context.Context, _ string) error { return nil },
		},
		&mockDeviceSessionRepo{
			saveDeviceSessionFunc: func(_ context.Context, _ *domain.DeviceSession) error { return nil },
			revokeDeviceFunc:      func(_ context.Context, _, _ string) error { return nil },
			revokeAllDevicesFunc:  func(_ context.Context, _ string) error { return nil },
			updateLastUsedAtFunc:  func(_ context.Context, _, _ string) error { return nil },
		},
		opts...,
	)
}

// ── VerifyToken + blacklist tests ─────────────────────────────────────────────

func TestVerifyToken_NoBlacklist_SkipsCheck(t *testing.T) {
	svc := blSvc(nil)
	result, err := svc.VerifyToken(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.KratosID == "" {
		t.Fatal("expected non-nil result with KratosID")
	}
}

func TestVerifyToken_NotRevoked_ReturnsResult(t *testing.T) {
	bl := &controllableBlacklist{isBlacklistedFunc: func(_ context.Context, _ string) (bool, error) {
		return false, nil
	}}
	result, err := blSvc(bl).VerifyToken(context.Background(), "tok")
	if err != nil || result == nil || result.KratosID != "kratos-1" {
		t.Fatalf("expected valid result: result=%v err=%v", result, err)
	}
}

func TestVerifyToken_DeviceKeyRevoked_ReturnsError(t *testing.T) {
	bl := &controllableBlacklist{isBlacklistedFunc: func(_ context.Context, key string) (bool, error) {
		return key == "device:kratos-1:dev-1", nil
	}}
	_, err := blSvc(bl).VerifyToken(context.Background(), "tok")
	if !errors.Is(err, service.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked for device key, got %v", err)
	}
}

func TestVerifyToken_UserKeyRevoked_ReturnsError(t *testing.T) {
	bl := &controllableBlacklist{isBlacklistedFunc: func(_ context.Context, key string) (bool, error) {
		// device key not revoked, but user key is
		return key == "user:kratos-1", nil
	}}
	_, err := blSvc(bl).VerifyToken(context.Background(), "tok")
	if !errors.Is(err, service.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked for user key, got %v", err)
	}
}

func TestVerifyToken_BlacklistError_FailClosed(t *testing.T) {
	bl := &controllableBlacklist{isBlacklistedFunc: func(_ context.Context, _ string) (bool, error) {
		return false, errors.New("pg: connection refused")
	}}
	_, err := blSvc(bl).VerifyToken(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error when blacklist returns error (fail-closed)")
	}
}

// ── Logout + blacklist tests ──────────────────────────────────────────────────

func TestLogout_WritesDeviceKey_ToBlacklist(t *testing.T) {
	bl := &controllableBlacklist{}
	if err := blSvc(bl).Logout(context.Background(), "refresh-tok"); err != nil {
		t.Fatalf("Logout error: %v", err)
	}
	wantKey := "device:kratos-1:dev-1"
	for _, k := range bl.addKeys {
		if k == wantKey {
			return
		}
	}
	t.Fatalf("expected blacklist.Add called with %q; got keys: %v", wantKey, bl.addKeys)
}

func TestLogout_BlacklistWriteError_ErrRedisUnavailable_IsNonFatal(t *testing.T) {
	bl := &controllableBlacklist{addErr: resilience.ErrRedisUnavailable}
	if err := blSvc(bl).Logout(context.Background(), "refresh-tok"); err != nil {
		t.Fatalf("expected no error when blacklist returns ErrRedisUnavailable; got: %v", err)
	}
}

func TestLogout_BlacklistWriteError_HardError_IsFatal(t *testing.T) {
	bl := &controllableBlacklist{addErr: errors.New("pg: down")}
	if err := blSvc(bl).Logout(context.Background(), "refresh-tok"); err == nil {
		t.Fatal("expected error when blacklist.Add fails with a hard error")
	}
}

// ── LogoutAll + blacklist tests ───────────────────────────────────────────────

func TestLogoutAll_WritesUserKey_ToBlacklist(t *testing.T) {
	bl := &controllableBlacklist{}
	if err := blSvc(bl).LogoutAll(context.Background(), "refresh-tok"); err != nil {
		t.Fatalf("LogoutAll error: %v", err)
	}
	wantKey := "user:kratos-1"
	for _, k := range bl.addKeys {
		if k == wantKey {
			return
		}
	}
	t.Fatalf("expected blacklist.Add called with %q; got keys: %v", wantKey, bl.addKeys)
}

func TestLogoutAll_BlacklistWriteError_ErrRedisUnavailable_IsNonFatal(t *testing.T) {
	bl := &controllableBlacklist{addErr: resilience.ErrRedisUnavailable}
	if err := blSvc(bl).LogoutAll(context.Background(), "refresh-tok"); err != nil {
		t.Fatalf("expected no error when blacklist returns ErrRedisUnavailable; got: %v", err)
	}
}
