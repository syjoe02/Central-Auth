package service_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"central-auth/internal/domain"
	"central-auth/internal/service"
	"central-auth/internal/token"
)

// ---- helpers ----------------------------------------------------------------

func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", "test-secret-that-is-at-least-32-chars!!")
	token.InitSecret()
	os.Exit(m.Run())
}

func makeRefreshToken(userID, deviceID string, ttl time.Duration) string {
	tok, err := token.Generate(userID, deviceID, token.TypeRefresh, ttl)
	if err != nil {
		panic(err)
	}
	return tok
}

// ---- mock RedisRepo ---------------------------------------------------------

type mockRedis struct {
	saveLoginFn          func(ctx context.Context, userID, deviceID, tok string, ttl time.Duration) error
	existsRefreshFn      func(ctx context.Context, userID, deviceID string) (bool, error)
	validateRefreshFn    func(ctx context.Context, userID, deviceID, tok string) (bool, error)
	rotateRefreshFn      func(ctx context.Context, userID, deviceID, newTok string, ttl time.Duration) error
	logoutDeviceFn       func(ctx context.Context, userID, deviceID string) error
	logoutAllFn          func(ctx context.Context, userID string) error
}

func (m *mockRedis) SaveLogin(ctx context.Context, userID, deviceID, tok string, ttl time.Duration) error {
	if m.saveLoginFn != nil {
		return m.saveLoginFn(ctx, userID, deviceID, tok, ttl)
	}
	return nil
}
func (m *mockRedis) ExistsRefreshToken(ctx context.Context, userID, deviceID string) (bool, error) {
	if m.existsRefreshFn != nil {
		return m.existsRefreshFn(ctx, userID, deviceID)
	}
	return true, nil
}
func (m *mockRedis) ValidateRefreshToken(ctx context.Context, userID, deviceID, tok string) (bool, error) {
	if m.validateRefreshFn != nil {
		return m.validateRefreshFn(ctx, userID, deviceID, tok)
	}
	return true, nil
}
func (m *mockRedis) RotateRefreshToken(ctx context.Context, userID, deviceID, newTok string, ttl time.Duration) error {
	if m.rotateRefreshFn != nil {
		return m.rotateRefreshFn(ctx, userID, deviceID, newTok, ttl)
	}
	return nil
}
func (m *mockRedis) LogoutDevice(ctx context.Context, userID, deviceID string) error {
	if m.logoutDeviceFn != nil {
		return m.logoutDeviceFn(ctx, userID, deviceID)
	}
	return nil
}
func (m *mockRedis) LogoutAll(ctx context.Context, userID string) error {
	if m.logoutAllFn != nil {
		return m.logoutAllFn(ctx, userID)
	}
	return nil
}

// ---- mock AuthUserRepository ------------------------------------------------

type mockUserRepo struct {
	findByProviderFn    func(ctx context.Context, provider, providerID string) (*domain.AuthUser, error)
	saveFn              func(ctx context.Context, user *domain.AuthUser) error
	saveRefreshFn       func(ctx context.Context, tok *domain.RefreshToken) error
	updateHashFn        func(ctx context.Context, userID, deviceID, hash string) error
	updateLastUsedFn    func(ctx context.Context, userID, deviceID string) error
	revokeDeviceFn      func(ctx context.Context, userID, deviceID string) error
	revokeAllFn         func(ctx context.Context, userID string) error
	getLoginDevicesFn   func(ctx context.Context, userID string) ([]domain.LoginDeviceInfo, error)
	countActiveDevFn    func(ctx context.Context, userID string) (int, error)
}

func (m *mockUserRepo) FindByProvider(ctx context.Context, provider, providerID string) (*domain.AuthUser, error) {
	if m.findByProviderFn != nil {
		return m.findByProviderFn(ctx, provider, providerID)
	}
	return nil, nil
}
func (m *mockUserRepo) Save(ctx context.Context, user *domain.AuthUser) error {
	if m.saveFn != nil {
		return m.saveFn(ctx, user)
	}
	return nil
}
func (m *mockUserRepo) SaveRefreshToken(ctx context.Context, tok *domain.RefreshToken) error {
	if m.saveRefreshFn != nil {
		return m.saveRefreshFn(ctx, tok)
	}
	return nil
}
func (m *mockUserRepo) UpdateTokenHash(ctx context.Context, userID, deviceID, hash string) error {
	if m.updateHashFn != nil {
		return m.updateHashFn(ctx, userID, deviceID, hash)
	}
	return nil
}
func (m *mockUserRepo) UpdateLastUsedAt(ctx context.Context, userID, deviceID string) error {
	if m.updateLastUsedFn != nil {
		return m.updateLastUsedFn(ctx, userID, deviceID)
	}
	return nil
}
func (m *mockUserRepo) RevokeDevice(ctx context.Context, userID, deviceID string) error {
	if m.revokeDeviceFn != nil {
		return m.revokeDeviceFn(ctx, userID, deviceID)
	}
	return nil
}
func (m *mockUserRepo) RevokeAllDevices(ctx context.Context, userID string) error {
	if m.revokeAllFn != nil {
		return m.revokeAllFn(ctx, userID)
	}
	return nil
}
func (m *mockUserRepo) GetLoginDevices(ctx context.Context, userID string) ([]domain.LoginDeviceInfo, error) {
	if m.getLoginDevicesFn != nil {
		return m.getLoginDevicesFn(ctx, userID)
	}
	return nil, nil
}
func (m *mockUserRepo) CountActiveDevices(ctx context.Context, userID string) (int, error) {
	if m.countActiveDevFn != nil {
		return m.countActiveDevFn(ctx, userID)
	}
	return 0, nil
}

// ---- Login ------------------------------------------------------------------

func TestLogin_HappyPath(t *testing.T) {
	svc := service.NewAuthService(&mockRedis{}, &mockUserRepo{})
	ctx := context.Background()

	access, refresh, err := svc.Login(ctx, "user-1", "device-1", false, nil, nil)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty tokens")
	}
}

func TestLogin_RememberMe_UsesLongTTL(t *testing.T) {
	var capturedTTL time.Duration
	redis := &mockRedis{
		saveLoginFn: func(_ context.Context, _, _, _ string, ttl time.Duration) error {
			capturedTTL = ttl
			return nil
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	_, _, err := svc.Login(context.Background(), "u", "d", true, nil, nil)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if capturedTTL != service.RefreshTTLLong {
		t.Errorf("expected TTL %v, got %v", service.RefreshTTLLong, capturedTTL)
	}
}

func TestLogin_RedisError_ReturnsError(t *testing.T) {
	sentinel := errors.New("redis down")
	redis := &mockRedis{
		saveLoginFn: func(_ context.Context, _, _, _ string, _ time.Duration) error {
			return sentinel
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	_, _, err := svc.Login(context.Background(), "u", "d", false, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestLogin_PostgresError_ReturnsError(t *testing.T) {
	sentinel := errors.New("pg down")
	userRepo := &mockUserRepo{
		saveRefreshFn: func(_ context.Context, _ *domain.RefreshToken) error {
			return sentinel
		},
	}
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	_, _, err := svc.Login(context.Background(), "u", "d", false, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

// ---- Logout -----------------------------------------------------------------

func TestLogout_HappyPath(t *testing.T) {
	ctx := context.Background()
	tok := makeRefreshToken("user-1", "device-1", time.Minute)

	svc := service.NewAuthService(&mockRedis{}, &mockUserRepo{})
	if err := svc.Logout(ctx, tok); err != nil {
		t.Fatalf("Logout: %v", err)
	}
}

func TestLogout_ExpiredToken_StillSucceeds(t *testing.T) {
	ctx := context.Background()
	tok := makeRefreshToken("user-1", "device-1", -time.Second)

	svc := service.NewAuthService(&mockRedis{}, &mockUserRepo{})
	if err := svc.Logout(ctx, tok); err != nil {
		t.Fatalf("Logout with expired token: %v", err)
	}
}

func TestLogout_InvalidToken_ReturnsError(t *testing.T) {
	svc := service.NewAuthService(&mockRedis{}, &mockUserRepo{})
	err := svc.Logout(context.Background(), "not-a-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// ---- LogoutAll --------------------------------------------------------------

func TestLogoutAll_ExpiredToken_StillSucceeds(t *testing.T) {
	ctx := context.Background()
	tok := makeRefreshToken("user-1", "device-1", -time.Second)

	svc := service.NewAuthService(&mockRedis{}, &mockUserRepo{})
	if err := svc.LogoutAll(ctx, tok); err != nil {
		t.Fatalf("LogoutAll with expired token: %v", err)
	}
}

// ---- Refresh ----------------------------------------------------------------

func TestRefresh_HappyPath(t *testing.T) {
	ctx := context.Background()
	original := makeRefreshToken("u", "d", time.Hour)

	redis := &mockRedis{
		validateRefreshFn: func(_ context.Context, _, _, tok string) (bool, error) {
			return tok == original, nil
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	newAccess, newRefresh, err := svc.Refresh(ctx, original)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if newAccess == "" || newRefresh == "" {
		t.Fatal("expected non-empty new tokens")
	}
	// Verify the new tokens are valid and correctly typed
	if _, err := token.ParseTyped(newAccess, token.TypeAccess); err != nil {
		t.Errorf("new access token invalid: %v", err)
	}
	if _, err := token.ParseTyped(newRefresh, token.TypeRefresh); err != nil {
		t.Errorf("new refresh token invalid: %v", err)
	}
}

func TestRefresh_InvalidToken_ReturnsError(t *testing.T) {
	svc := service.NewAuthService(&mockRedis{}, &mockUserRepo{})
	_, _, err := svc.Refresh(context.Background(), "bad-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestRefresh_TokenNotInRedis_ReturnsError(t *testing.T) {
	ctx := context.Background()
	tok := makeRefreshToken("u", "d", time.Hour)

	redis := &mockRedis{
		validateRefreshFn: func(_ context.Context, _, _, _ string) (bool, error) {
			return false, nil // not found / revoked
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	_, _, err := svc.Refresh(ctx, tok)
	if err == nil {
		t.Fatal("expected error when token not in Redis")
	}
}

// ---- OAuthLogin -------------------------------------------------------------

func TestOAuthLogin_NewUser(t *testing.T) {
	userRepo := &mockUserRepo{
		findByProviderFn: func(_ context.Context, _, _ string) (*domain.AuthUser, error) {
			return nil, nil // user does not exist yet
		},
	}
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	access, refresh, err := svc.OAuthLogin(
		context.Background(), "google", "provider-123", "test@example.com",
		"device-1", false, nil, nil,
	)
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty tokens")
	}
}

func TestOAuthLogin_ExistingUser(t *testing.T) {
	existing := &domain.AuthUser{
		UserID: "existing-uid", Provider: "google", ProviderID: "p-123", Email: "x@x.com",
	}
	saveCalled := false
	userRepo := &mockUserRepo{
		findByProviderFn: func(_ context.Context, _, _ string) (*domain.AuthUser, error) {
			return existing, nil
		},
		saveFn: func(_ context.Context, _ *domain.AuthUser) error {
			saveCalled = true
			return nil
		},
	}
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	_, _, err := svc.OAuthLogin(
		context.Background(), "google", "p-123", "x@x.com",
		"d", false, nil, nil,
	)
	if err != nil {
		t.Fatalf("OAuthLogin: %v", err)
	}
	if saveCalled {
		t.Error("Save should not be called for an existing user")
	}
}

func TestOAuthLogin_FindByProviderError(t *testing.T) {
	sentinel := errors.New("db error")
	userRepo := &mockUserRepo{
		findByProviderFn: func(_ context.Context, _, _ string) (*domain.AuthUser, error) {
			return nil, sentinel
		},
	}
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	_, _, err := svc.OAuthLogin(
		context.Background(), "google", "p", "e", "d", false, nil, nil,
	)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestOAuthLogin_SaveUserError(t *testing.T) {
	sentinel := errors.New("save failed")
	userRepo := &mockUserRepo{
		findByProviderFn: func(_ context.Context, _, _ string) (*domain.AuthUser, error) {
			return nil, nil
		},
		saveFn: func(_ context.Context, _ *domain.AuthUser) error {
			return sentinel
		},
	}
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	_, _, err := svc.OAuthLogin(
		context.Background(), "google", "p", "e", "d", false, nil, nil,
	)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestOAuthLogin_RedisError(t *testing.T) {
	sentinel := errors.New("redis error")
	redis := &mockRedis{
		saveLoginFn: func(_ context.Context, _, _, _ string, _ time.Duration) error {
			return sentinel
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	_, _, err := svc.OAuthLogin(
		context.Background(), "google", "p", "e", "d", false, nil, nil,
	)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

// ---- Logout error paths -----------------------------------------------------

func TestLogout_RedisError(t *testing.T) {
	sentinel := errors.New("redis error")
	redis := &mockRedis{
		logoutDeviceFn: func(_ context.Context, _, _ string) error {
			return sentinel
		},
	}
	tok := makeRefreshToken("u", "d", time.Minute)
	svc := service.NewAuthService(redis, &mockUserRepo{})

	err := svc.Logout(context.Background(), tok)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestLogout_PostgresError(t *testing.T) {
	sentinel := errors.New("pg error")
	userRepo := &mockUserRepo{
		revokeDeviceFn: func(_ context.Context, _, _ string) error {
			return sentinel
		},
	}
	tok := makeRefreshToken("u", "d", time.Minute)
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	err := svc.Logout(context.Background(), tok)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestLogoutAll_RedisError(t *testing.T) {
	sentinel := errors.New("redis error")
	redis := &mockRedis{
		logoutAllFn: func(_ context.Context, _ string) error {
			return sentinel
		},
	}
	tok := makeRefreshToken("u", "d", time.Minute)
	svc := service.NewAuthService(redis, &mockUserRepo{})

	err := svc.LogoutAll(context.Background(), tok)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestLogoutAll_PostgresError(t *testing.T) {
	sentinel := errors.New("pg error")
	userRepo := &mockUserRepo{
		revokeAllFn: func(_ context.Context, _ string) error {
			return sentinel
		},
	}
	tok := makeRefreshToken("u", "d", time.Minute)
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	err := svc.LogoutAll(context.Background(), tok)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestLogoutAll_InvalidToken_ReturnsError(t *testing.T) {
	svc := service.NewAuthService(&mockRedis{}, &mockUserRepo{})
	err := svc.LogoutAll(context.Background(), "not-a-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// ---- Refresh error paths ----------------------------------------------------

func TestRefresh_ValidateRedisError(t *testing.T) {
	sentinel := errors.New("redis error")
	original := makeRefreshToken("u", "d", time.Hour)

	redis := &mockRedis{
		validateRefreshFn: func(_ context.Context, _, _, _ string) (bool, error) {
			return false, sentinel
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	_, _, err := svc.Refresh(context.Background(), original)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestRefresh_RotateError(t *testing.T) {
	sentinel := errors.New("rotate error")
	original := makeRefreshToken("u", "d", time.Hour)

	redis := &mockRedis{
		validateRefreshFn: func(_ context.Context, _, _, _ string) (bool, error) {
			return true, nil
		},
		rotateRefreshFn: func(_ context.Context, _, _, _ string, _ time.Duration) error {
			return sentinel
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	_, _, err := svc.Refresh(context.Background(), original)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestRefresh_UpdateHashError(t *testing.T) {
	sentinel := errors.New("pg error")
	original := makeRefreshToken("u", "d", time.Hour)

	userRepo := &mockUserRepo{
		updateHashFn: func(_ context.Context, _, _, _ string) error {
			return sentinel
		},
	}
	svc := service.NewAuthService(&mockRedis{}, userRepo)

	_, _, err := svc.Refresh(context.Background(), original)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

// ---- ExistsSession ----------------------------------------------------------

func TestExistsSession_Exists(t *testing.T) {
	redis := &mockRedis{
		existsRefreshFn: func(_ context.Context, _, _ string) (bool, error) {
			return true, nil
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	exists, err := svc.ExistsSession(context.Background(), "u", "d")
	if err != nil {
		t.Fatalf("ExistsSession: %v", err)
	}
	if !exists {
		t.Error("expected session to exist")
	}
}

func TestExistsSession_NotExists(t *testing.T) {
	redis := &mockRedis{
		existsRefreshFn: func(_ context.Context, _, _ string) (bool, error) {
			return false, nil
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	exists, err := svc.ExistsSession(context.Background(), "u", "d")
	if err != nil {
		t.Fatalf("ExistsSession: %v", err)
	}
	if exists {
		t.Error("expected session to not exist")
	}
}

func TestExistsSession_RedisError(t *testing.T) {
	sentinel := errors.New("redis down")
	redis := &mockRedis{
		existsRefreshFn: func(_ context.Context, _, _ string) (bool, error) {
			return false, sentinel
		},
	}
	svc := service.NewAuthService(redis, &mockUserRepo{})

	_, err := svc.ExistsSession(context.Background(), "u", "d")
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}
