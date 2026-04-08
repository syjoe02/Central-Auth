package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"central-auth/internal/domain"
	"central-auth/internal/hydra"
	"central-auth/internal/service"
)

// ── Mock: HydraClient ────────────────────────────────────────────────────────

type mockHydraClient struct {
	issueTokensFunc       func(ctx context.Context, kratosID, deviceID string, rememberMe bool) (*hydra.TokenSet, error)
	refreshTokenFunc      func(ctx context.Context, refreshToken string) (*hydra.TokenSet, error)
	revokeTokenFunc       func(ctx context.Context, token string) error
	revokeAllFunc         func(ctx context.Context, kratosID string) error
	introspectFunc        func(ctx context.Context, token string) (*hydra.IntrospectResult, error)
	validateAccessFunc    func(ctx context.Context, token string) (*hydra.AccessTokenClaims, error)
}

func (m *mockHydraClient) IssueTokens(ctx context.Context, kratosID, deviceID string, rememberMe bool) (*hydra.TokenSet, error) {
	return m.issueTokensFunc(ctx, kratosID, deviceID, rememberMe)
}
func (m *mockHydraClient) RefreshToken(ctx context.Context, token string) (*hydra.TokenSet, error) {
	return m.refreshTokenFunc(ctx, token)
}
func (m *mockHydraClient) RevokeToken(ctx context.Context, token string) error {
	return m.revokeTokenFunc(ctx, token)
}
func (m *mockHydraClient) RevokeAllForSubject(ctx context.Context, kratosID string) error {
	return m.revokeAllFunc(ctx, kratosID)
}
func (m *mockHydraClient) IntrospectToken(ctx context.Context, token string) (*hydra.IntrospectResult, error) {
	return m.introspectFunc(ctx, token)
}
func (m *mockHydraClient) ValidateAccessToken(ctx context.Context, token string) (*hydra.AccessTokenClaims, error) {
	if m.validateAccessFunc == nil {
		return nil, errors.New("validateAccessFunc not configured")
	}
	return m.validateAccessFunc(ctx, token)
}
func (m *mockHydraClient) ForceRefreshJWKS(_ context.Context) error { return nil }

// ── Mock: RedisRepo ──────────────────────────────────────────────────────────

type mockRedisRepo struct {
	saveLoginFunc           func(ctx context.Context, kratosID, deviceID, token string, ttl time.Duration) error
	getDeviceRefreshFunc    func(ctx context.Context, kratosID, deviceID string) (string, error)
	rotateRefreshTokenFunc  func(ctx context.Context, kratosID, deviceID, newToken string, ttl time.Duration) error
	logoutDeviceFunc        func(ctx context.Context, kratosID, deviceID string) error
	logoutAllFunc           func(ctx context.Context, kratosID string) error
}

func (m *mockRedisRepo) SaveLogin(ctx context.Context, kratosID, deviceID, token string, ttl time.Duration) error {
	return m.saveLoginFunc(ctx, kratosID, deviceID, token, ttl)
}
func (m *mockRedisRepo) GetDeviceRefreshToken(ctx context.Context, kratosID, deviceID string) (string, error) {
	return m.getDeviceRefreshFunc(ctx, kratosID, deviceID)
}
func (m *mockRedisRepo) RotateRefreshToken(ctx context.Context, kratosID, deviceID, newToken string, ttl time.Duration) error {
	return m.rotateRefreshTokenFunc(ctx, kratosID, deviceID, newToken, ttl)
}
func (m *mockRedisRepo) LogoutDevice(ctx context.Context, kratosID, deviceID string) error {
	return m.logoutDeviceFunc(ctx, kratosID, deviceID)
}
func (m *mockRedisRepo) LogoutAll(ctx context.Context, kratosID string) error {
	return m.logoutAllFunc(ctx, kratosID)
}

// ── Mock: DeviceSessionRepository ───────────────────────────────────────────

type mockDeviceSessionRepo struct {
	saveDeviceSessionFunc   func(ctx context.Context, session *domain.DeviceSession) error
	updateLastUsedAtFunc    func(ctx context.Context, kratosID, deviceID string) error
	revokeDeviceFunc        func(ctx context.Context, kratosID, deviceID string) error
	revokeAllDevicesFunc    func(ctx context.Context, kratosID string) error
	getDeviceSessionsFunc   func(ctx context.Context, kratosID string) ([]domain.DeviceSession, error)
	countActiveDevicesFunc  func(ctx context.Context, kratosID string) (int, error)
}

func (m *mockDeviceSessionRepo) SaveDeviceSession(ctx context.Context, session *domain.DeviceSession) error {
	return m.saveDeviceSessionFunc(ctx, session)
}
func (m *mockDeviceSessionRepo) UpdateLastUsedAt(ctx context.Context, kratosID, deviceID string) error {
	return m.updateLastUsedAtFunc(ctx, kratosID, deviceID)
}
func (m *mockDeviceSessionRepo) RevokeDevice(ctx context.Context, kratosID, deviceID string) error {
	return m.revokeDeviceFunc(ctx, kratosID, deviceID)
}
func (m *mockDeviceSessionRepo) RevokeAllDevices(ctx context.Context, kratosID string) error {
	return m.revokeAllDevicesFunc(ctx, kratosID)
}
func (m *mockDeviceSessionRepo) GetDeviceSessions(ctx context.Context, kratosID string) ([]domain.DeviceSession, error) {
	return m.getDeviceSessionsFunc(ctx, kratosID)
}
func (m *mockDeviceSessionRepo) CountActiveDevices(ctx context.Context, kratosID string) (int, error) {
	return m.countActiveDevicesFunc(ctx, kratosID)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func noopSaveSession(ctx context.Context, _ *domain.DeviceSession) error    { return nil }
func noopUpdateLastUsed(ctx context.Context, _, _ string) error             { return nil }
func noopRevokeDevice(ctx context.Context, _, _ string) error               { return nil }
func noopRevokeAll(ctx context.Context, _ string) error                     { return nil }
func noopGetSessions(ctx context.Context, _ string) ([]domain.DeviceSession, error) {
	return nil, nil
}
func noopCountActive(ctx context.Context, _ string) (int, error) { return 0, nil }

func noopSaveLogin(ctx context.Context, _, _, _ string, _ time.Duration) error { return nil }
func noopRotate(ctx context.Context, _, _, _ string, _ time.Duration) error    { return nil }
func noopLogoutDevice(ctx context.Context, _, _ string) error                  { return nil }
func noopLogoutAll(ctx context.Context, _ string) error                        { return nil }
func noopGetRefresh(ctx context.Context, _, _ string) (string, error)          { return "", nil }

func goodTokens() *hydra.TokenSet {
	return &hydra.TokenSet{
		AccessToken:  "access.token.jwt",
		RefreshToken: "opaque-refresh-token",
		TokenType:    "bearer",
		ExpiresIn:    900,
	}
}

func goodClaims(kratosID, deviceID string) *hydra.AccessTokenClaims {
	return &hydra.AccessTokenClaims{
		Subject: kratosID,
		Ext:     map[string]interface{}{"device_id": deviceID},
	}
}

// ── Test: Login ──────────────────────────────────────────────────────────────

func TestLogin_HappyPath(t *testing.T) {
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, kratosID, deviceID string, rememberMe bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
	}
	r := &mockRedisRepo{saveLoginFunc: noopSaveLogin}
	d := &mockDeviceSessionRepo{
		saveDeviceSessionFunc: noopSaveSession,
	}

	svc := service.NewOryAuthService(h, r, d)
	access, refresh, err := svc.Login(context.Background(), "kratos-id-1", "device-1", false, nil, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty tokens")
	}
}

func TestLogin_RememberMe_UsesLongTTL(t *testing.T) {
	var savedTTL time.Duration
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
	}
	r := &mockRedisRepo{
		saveLoginFunc: func(_ context.Context, _, _, _ string, ttl time.Duration) error {
			savedTTL = ttl
			return nil
		},
	}
	d := &mockDeviceSessionRepo{saveDeviceSessionFunc: noopSaveSession}

	svc := service.NewOryAuthService(h, r, d)
	_, _, err := svc.Login(context.Background(), "k1", "d1", true, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if savedTTL != service.RefreshTTLLong {
		t.Errorf("expected RefreshTTLLong (%v), got %v", service.RefreshTTLLong, savedTTL)
	}
}

func TestLogin_HydraError_ReturnsError(t *testing.T) {
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return nil, errors.New("hydra: network error")
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	_, _, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLogin_RedisError_ReturnsError(t *testing.T) {
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
	}
	r := &mockRedisRepo{
		saveLoginFunc: func(_ context.Context, _, _, _ string, _ time.Duration) error {
			return errors.New("redis: connection refused")
		},
	}
	svc := service.NewOryAuthService(h, r, &mockDeviceSessionRepo{})
	_, _, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ── Test: Logout ─────────────────────────────────────────────────────────────

func TestLogout_HappyPath(t *testing.T) {
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return &hydra.IntrospectResult{
				Active:  true,
				Subject: "kratos-id-1",
				Ext:     map[string]interface{}{"device_id": "device-1"},
			}, nil
		},
		revokeTokenFunc: func(_ context.Context, _ string) error { return nil },
	}
	r := &mockRedisRepo{logoutDeviceFunc: noopLogoutDevice}
	d := &mockDeviceSessionRepo{revokeDeviceFunc: noopRevokeDevice}

	svc := service.NewOryAuthService(h, r, d)
	if err := svc.Logout(context.Background(), "opaque-refresh-token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogout_InactiveToken_ReturnsErrInvalidToken(t *testing.T) {
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return &hydra.IntrospectResult{Active: false}, nil
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	err := svc.Logout(context.Background(), "bad-token")
	if !errors.Is(err, service.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLogout_IntrospectError_ReturnsErrInvalidToken(t *testing.T) {
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return nil, errors.New("hydra: introspect failed")
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	err := svc.Logout(context.Background(), "bad-token")
	if !errors.Is(err, service.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLogout_MissingDeviceID_ReturnsErrInvalidToken(t *testing.T) {
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return &hydra.IntrospectResult{Active: true, Subject: "k1"}, nil // no device_id
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	err := svc.Logout(context.Background(), "token")
	if !errors.Is(err, service.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLogout_RedisFailure_IsNonFatal(t *testing.T) {
	// Redis cleanup failure should NOT cause Logout to return an error
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return &hydra.IntrospectResult{
				Active:  true,
				Subject: "k1",
				Ext:     map[string]interface{}{"device_id": "d1"},
			}, nil
		},
		revokeTokenFunc: func(_ context.Context, _ string) error { return nil },
	}
	r := &mockRedisRepo{
		logoutDeviceFunc: func(_ context.Context, _, _ string) error {
			return errors.New("redis: connection refused")
		},
	}
	d := &mockDeviceSessionRepo{revokeDeviceFunc: noopRevokeDevice}

	svc := service.NewOryAuthService(h, r, d)
	if err := svc.Logout(context.Background(), "token"); err != nil {
		t.Fatalf("Redis failure should be non-fatal, got: %v", err)
	}
}

// ── Test: LogoutAll ──────────────────────────────────────────────────────────

func TestLogoutAll_HappyPath(t *testing.T) {
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return &hydra.IntrospectResult{Active: true, Subject: "k1"}, nil
		},
		revokeAllFunc: func(_ context.Context, _ string) error { return nil },
	}
	r := &mockRedisRepo{logoutAllFunc: noopLogoutAll}
	d := &mockDeviceSessionRepo{revokeAllDevicesFunc: noopRevokeAll}

	svc := service.NewOryAuthService(h, r, d)
	if err := svc.LogoutAll(context.Background(), "token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogoutAll_InactiveToken_ReturnsErrInvalidToken(t *testing.T) {
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return &hydra.IntrospectResult{Active: false}, nil
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	err := svc.LogoutAll(context.Background(), "bad-token")
	if !errors.Is(err, service.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLogoutAll_HydraRevokeAllError_ReturnsError(t *testing.T) {
	h := &mockHydraClient{
		introspectFunc: func(_ context.Context, _ string) (*hydra.IntrospectResult, error) {
			return &hydra.IntrospectResult{Active: true, Subject: "k1"}, nil
		},
		revokeAllFunc: func(_ context.Context, _ string) error {
			return errors.New("hydra: admin API down")
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	if err := svc.LogoutAll(context.Background(), "token"); err == nil {
		t.Fatal("expected error from Hydra revoke-all failure")
	}
}

// ── Test: Refresh ────────────────────────────────────────────────────────────

func TestRefresh_HappyPath(t *testing.T) {
	newTokens := &hydra.TokenSet{AccessToken: "new.access.jwt", RefreshToken: "new-refresh", ExpiresIn: 900}
	h := &mockHydraClient{
		refreshTokenFunc: func(_ context.Context, _ string) (*hydra.TokenSet, error) {
			return newTokens, nil
		},
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return &hydra.AccessTokenClaims{
				Subject: "k1",
				Ext:     map[string]interface{}{"device_id": "d1"},
			}, nil
		},
	}
	r := &mockRedisRepo{rotateRefreshTokenFunc: noopRotate}
	d := &mockDeviceSessionRepo{updateLastUsedAtFunc: noopUpdateLastUsed}

	svc := service.NewOryAuthService(h, r, d)
	access, refresh, err := svc.Refresh(context.Background(), "old-refresh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if access != newTokens.AccessToken || refresh != newTokens.RefreshToken {
		t.Errorf("token mismatch: got access=%q refresh=%q", access, refresh)
	}
}

func TestRefresh_HydraError_ReturnsErrInvalidToken(t *testing.T) {
	h := &mockHydraClient{
		refreshTokenFunc: func(_ context.Context, _ string) (*hydra.TokenSet, error) {
			return nil, errors.New("hydra: invalid refresh token")
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	_, _, err := svc.Refresh(context.Background(), "bad-refresh")
	if !errors.Is(err, service.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestRefresh_RedisRotateFailure_IsNonFatal(t *testing.T) {
	h := &mockHydraClient{
		refreshTokenFunc: func(_ context.Context, _ string) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return &hydra.AccessTokenClaims{
				Subject: "k1",
				Ext:     map[string]interface{}{"device_id": "d1"},
			}, nil
		},
	}
	r := &mockRedisRepo{
		rotateRefreshTokenFunc: func(_ context.Context, _, _, _ string, _ time.Duration) error {
			return errors.New("redis: down")
		},
	}
	d := &mockDeviceSessionRepo{updateLastUsedAtFunc: noopUpdateLastUsed}

	svc := service.NewOryAuthService(h, r, d)
	_, _, err := svc.Refresh(context.Background(), "refresh")
	if err != nil {
		t.Fatalf("Redis failure should be non-fatal, got: %v", err)
	}
}

// ── Test: VerifyToken ────────────────────────────────────────────────────────

func TestVerifyToken_HappyPath(t *testing.T) {
	h := &mockHydraClient{
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			exp := time.Now().Add(15 * time.Minute)
			claims := &hydra.AccessTokenClaims{
				Subject: "kratos-id-1",
				Ext:     map[string]interface{}{"device_id": "device-1"},
			}
			_ = exp
			return claims, nil
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	result, err := svc.VerifyToken(context.Background(), "access.jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KratosID != "kratos-id-1" {
		t.Errorf("expected KratosID=kratos-id-1, got %q", result.KratosID)
	}
	if result.DeviceID != "device-1" {
		t.Errorf("expected DeviceID=device-1, got %q", result.DeviceID)
	}
}

func TestVerifyToken_InvalidJWT_ReturnsFail(t *testing.T) {
	h := &mockHydraClient{
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return nil, errors.New("hydra: invalid signature")
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	_, err := svc.VerifyToken(context.Background(), "bad.jwt")
	if err == nil {
		t.Fatal("expected error for invalid JWT")
	}
}

func TestVerifyToken_JWKSUnavailable_FailClosed(t *testing.T) {
	// Fail-closed: even if Hydra JWKS endpoint is down, Verify returns an error (→ 401)
	h := &mockHydraClient{
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return nil, errors.New("hydra: JWKS fetch failed: connection refused")
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	_, err := svc.VerifyToken(context.Background(), "some.jwt")
	if err == nil {
		t.Fatal("expected error when JWKS unavailable (fail-closed)")
	}
}

func TestVerifyToken_MissingDeviceID_ReturnsFail(t *testing.T) {
	h := &mockHydraClient{
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return &hydra.AccessTokenClaims{Subject: "k1"}, nil // no device_id in Ext
		},
	}
	svc := service.NewOryAuthService(h, &mockRedisRepo{}, &mockDeviceSessionRepo{})
	_, err := svc.VerifyToken(context.Background(), "jwt")
	if err == nil {
		t.Fatal("expected error for missing device_id claim")
	}
}

// ── Test: Login async Kafka path ─────────────────────────────────────────────

func TestLogin_PublishesAuthSessionEvent_WithJTI(t *testing.T) {
	pub := &mockEventPublisher{}
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			c := goodClaims("kratos-id-1", "device-1")
			c.ID = "jti-from-hydra"
			return c, nil
		},
	}
	r := &mockRedisRepo{saveLoginFunc: noopSaveLogin}

	svc := service.NewOryAuthService(h, r, &mockDeviceSessionRepo{}, service.WithEventPublisher(pub))
	_, _, err := svc.Login(context.Background(), "kratos-id-1", "device-1", false, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pub.authSessions) != 1 {
		t.Fatalf("expected 1 AuthSessionEvent published, got %d", len(pub.authSessions))
	}
	ev := pub.authSessions[0]
	if ev.EventType != "auth.session.created" {
		t.Errorf("EventType: want auth.session.created, got %s", ev.EventType)
	}
	if ev.KratosID != "kratos-id-1" {
		t.Errorf("KratosID: want kratos-id-1, got %s", ev.KratosID)
	}
	if ev.HydraJTI != "jti-from-hydra" {
		t.Errorf("HydraJTI: want jti-from-hydra, got %s", ev.HydraJTI)
	}
}

func TestLogin_ValidateTokenFailure_StillSucceeds_EmptyJTI(t *testing.T) {
	pub := &mockEventPublisher{}
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
		validateAccessFunc: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return nil, errors.New("jwks unavailable")
		},
	}
	r := &mockRedisRepo{saveLoginFunc: noopSaveLogin}

	svc := service.NewOryAuthService(h, r, &mockDeviceSessionRepo{}, service.WithEventPublisher(pub))
	access, refresh, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil)
	if err != nil {
		t.Fatalf("login must succeed even when ValidateAccessToken fails, got: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty tokens")
	}
	if len(pub.authSessions) != 1 {
		t.Fatalf("expected 1 event even with empty JTI, got %d", len(pub.authSessions))
	}
	if pub.authSessions[0].HydraJTI != "" {
		t.Errorf("expected empty HydraJTI on validate failure, got %q", pub.authSessions[0].HydraJTI)
	}
}

func TestLogin_NoSynchronousDeviceSessionSave(t *testing.T) {
	saveCalled := false
	d := &mockDeviceSessionRepo{
		saveDeviceSessionFunc: func(_ context.Context, _ *domain.DeviceSession) error {
			saveCalled = true
			return nil
		},
	}
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
	}
	r := &mockRedisRepo{saveLoginFunc: noopSaveLogin}

	svc := service.NewOryAuthService(h, r, d)
	if _, _, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saveCalled {
		t.Error("SaveDeviceSession must not be called synchronously in Login (async via Kafka consumer)")
	}
}

func TestLogin_PublishedEventTimestampIsRFC3339Nano(t *testing.T) {
	pub := &mockEventPublisher{}
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
	}
	r := &mockRedisRepo{saveLoginFunc: noopSaveLogin}

	svc := service.NewOryAuthService(h, r, &mockDeviceSessionRepo{}, service.WithEventPublisher(pub))
	if _, _, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pub.authSessions) != 1 {
		t.Fatalf("expected 1 event, got %d", len(pub.authSessions))
	}
	if _, err := time.Parse(time.RFC3339Nano, pub.authSessions[0].Timestamp); err != nil {
		t.Errorf("Timestamp %q is not RFC3339Nano: %v", pub.authSessions[0].Timestamp, err)
	}
}

func TestLogin_IPAndUserAgent_InPublishedEvent(t *testing.T) {
	pub := &mockEventPublisher{}
	h := &mockHydraClient{
		issueTokensFunc: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return goodTokens(), nil
		},
	}
	r := &mockRedisRepo{saveLoginFunc: noopSaveLogin}
	ua := "Mozilla/5.0"
	ip := "10.0.0.1"

	svc := service.NewOryAuthService(h, r, &mockDeviceSessionRepo{}, service.WithEventPublisher(pub))
	if _, _, err := svc.Login(context.Background(), "k1", "d1", false, &ua, &ip); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pub.authSessions) != 1 {
		t.Fatalf("expected 1 event, got %d", len(pub.authSessions))
	}
	ev := pub.authSessions[0]
	if ev.IPAddress != "10.0.0.1" {
		t.Errorf("IPAddress: want 10.0.0.1, got %q", ev.IPAddress)
	}
	if ev.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent: want Mozilla/5.0, got %q", ev.UserAgent)
	}
}
