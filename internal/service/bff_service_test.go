package service_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"central-auth/internal/blacklist"
	"central-auth/internal/config"
	"central-auth/internal/domain"
	"central-auth/internal/hydra"
	"central-auth/internal/kafka"
	"central-auth/internal/repository"
	"central-auth/internal/service"
	"central-auth/internal/session"

	"github.com/golang-jwt/jwt/v5"
)

// ── mock implementations ──────────────────────────────────────────────────────

type mockHydra struct {
	issueTokensFn         func(ctx context.Context, kratosID, deviceID string, rememberMe bool) (*hydra.TokenSet, error)
	refreshTokenFn        func(ctx context.Context, refreshToken string) (*hydra.TokenSet, error)
	revokeTokenFn         func(ctx context.Context, token string) error
	revokeAllFn           func(ctx context.Context, kratosID string) error
	introspectFn          func(ctx context.Context, token string) (*hydra.IntrospectResult, error)
	validateAccessTokenFn func(ctx context.Context, tokenStr string) (*hydra.AccessTokenClaims, error)
	forceRefreshJWKSFn    func(ctx context.Context) error
}

func (m *mockHydra) IssueTokens(ctx context.Context, k, d string, r bool) (*hydra.TokenSet, error) {
	return m.issueTokensFn(ctx, k, d, r)
}
func (m *mockHydra) RefreshToken(ctx context.Context, t string) (*hydra.TokenSet, error) {
	return m.refreshTokenFn(ctx, t)
}
func (m *mockHydra) RevokeToken(ctx context.Context, t string) error { return m.revokeTokenFn(ctx, t) }
func (m *mockHydra) RevokeAllForSubject(ctx context.Context, k string) error {
	return m.revokeAllFn(ctx, k)
}
func (m *mockHydra) IntrospectToken(ctx context.Context, t string) (*hydra.IntrospectResult, error) {
	return m.introspectFn(ctx, t)
}
func (m *mockHydra) ValidateAccessToken(ctx context.Context, t string) (*hydra.AccessTokenClaims, error) {
	return m.validateAccessTokenFn(ctx, t)
}
func (m *mockHydra) ForceRefreshJWKS(ctx context.Context) error {
	return m.forceRefreshJWKSFn(ctx)
}

type mockSessionStore struct {
	sessions map[string]session.BFFSession
}

func newMockStore() *mockSessionStore {
	return &mockSessionStore{sessions: make(map[string]session.BFFSession)}
}
func (m *mockSessionStore) Create(ctx context.Context, s session.BFFSession) error {
	m.sessions[s.SessionID] = s
	return nil
}
func (m *mockSessionStore) Get(ctx context.Context, id string) (session.BFFSession, error) {
	s, ok := m.sessions[id]
	if !ok {
		return session.BFFSession{}, session.ErrNotFound
	}
	return s, nil
}
func (m *mockSessionStore) Update(ctx context.Context, s session.BFFSession) error {
	m.sessions[s.SessionID] = s
	return nil
}
func (m *mockSessionStore) Delete(ctx context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}
func (m *mockSessionStore) GetAllForUser(ctx context.Context, kratosID string) ([]session.BFFSession, error) {
	var result []session.BFFSession
	for _, s := range m.sessions {
		if s.KratosID == kratosID {
			result = append(result, s)
		}
	}
	return result, nil
}
func (m *mockSessionStore) DeleteAllForUser(ctx context.Context, kratosID string) ([]string, error) {
	var ids []string
	for id, s := range m.sessions {
		if s.KratosID == kratosID {
			ids = append(ids, id)
			delete(m.sessions, id)
		}
	}
	return ids, nil
}
func (m *mockSessionStore) AcquireRefreshLock(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	return true, nil // always grants lock in tests
}
func (m *mockSessionStore) ReleaseRefreshLock(ctx context.Context, id string) error { return nil }

type mockBlacklist struct {
	entries map[string]bool
}

func newMockBlacklist() *mockBlacklist {
	return &mockBlacklist{entries: make(map[string]bool)}
}
func (m *mockBlacklist) Add(ctx context.Context, id string, ttl time.Duration) error {
	m.entries[id] = true
	return nil
}
func (m *mockBlacklist) IsBlacklisted(ctx context.Context, id string) (bool, error) {
	return m.entries[id], nil
}
func (m *mockBlacklist) AddBatch(ctx context.Context, ids []string, ttl time.Duration) error {
	for _, id := range ids {
		m.entries[id] = true
	}
	return nil
}

type bffMockRedisRepo struct{}

func (m *bffMockRedisRepo) SaveLogin(ctx context.Context, k, d, t string, ttl time.Duration) error {
	return nil
}
func (m *bffMockRedisRepo) GetDeviceRefreshToken(ctx context.Context, k, d string) (string, error) {
	return "", nil
}
func (m *bffMockRedisRepo) RotateRefreshToken(ctx context.Context, k, d, t string, ttl time.Duration) error {
	return nil
}
func (m *bffMockRedisRepo) LogoutDevice(ctx context.Context, k, d string) error { return nil }
func (m *bffMockRedisRepo) LogoutAll(ctx context.Context, k string) error        { return nil }

type bffMockDeviceSessionRepo struct{}

func (m *bffMockDeviceSessionRepo) SaveDeviceSession(ctx context.Context, s *domain.DeviceSession) error {
	return nil
}
func (m *bffMockDeviceSessionRepo) UpdateLastUsedAt(ctx context.Context, k, d string) error { return nil }
func (m *bffMockDeviceSessionRepo) RevokeDevice(ctx context.Context, k, d string) error     { return nil }
func (m *bffMockDeviceSessionRepo) RevokeAllDevices(ctx context.Context, k string) error    { return nil }
func (m *bffMockDeviceSessionRepo) GetDeviceSessions(ctx context.Context, k string) ([]domain.DeviceSession, error) {
	return nil, nil
}
func (m *bffMockDeviceSessionRepo) CountActiveDevices(ctx context.Context, k string) (int, error) {
	return 0, nil
}

// mockEventPublisher records PublishAuthSession calls for test assertions.
type mockEventPublisher struct {
	authSessions []kafka.AuthSessionEvent
}

func (m *mockEventPublisher) Publish(_ kafka.AccessLogEvent) {}
func (m *mockEventPublisher) PublishAuthSession(e kafka.AuthSessionEvent) {
	m.authSessions = append(m.authSessions, e)
}
func (m *mockEventPublisher) PublishBlacklistSync(_ kafka.BlacklistSyncEvent) {}
func (m *mockEventPublisher) Close(_ context.Context) error                   { return nil }

// compile-time interface checks
var _ hydra.ClientI = (*mockHydra)(nil)
var _ session.Store = (*mockSessionStore)(nil)
var _ blacklist.Blacklist = (*mockBlacklist)(nil)
var _ repository.RedisRepo = (*bffMockRedisRepo)(nil)
var _ repository.DeviceSessionRepository = (*bffMockDeviceSessionRepo)(nil)
var _ kafka.EventPublisher = (*mockEventPublisher)(nil)

// ── helpers ───────────────────────────────────────────────────────────────────

func testCfg() config.BFFConfig {
	return config.BFFConfig{
		CookieDomain:             "example.com",
		CookieSecure:             true,
		SessionTTL:               7 * 24 * time.Hour,
		CSRFSecret:               "testsecret",
		JWKSGracePeriod:          30 * time.Minute,
		AccessTokenRefreshBuffer: 60 * time.Second,
	}
}

func bffGoodClaims(kratosID, deviceID string) *hydra.AccessTokenClaims {
	exp := jwt.NewNumericDate(time.Now().Add(15 * time.Minute))
	return &hydra.AccessTokenClaims{
		Subject:          kratosID,
		Ext:              map[string]interface{}{"device_id": deviceID},
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: exp, ID: "test-jti"},
	}
}

func newBFFService(h *mockHydra, store session.Store, bl blacklist.Blacklist) *service.BFFService {
	return service.NewBFFService(h, store, bl, &bffMockRedisRepo{}, &bffMockDeviceSessionRepo{}, testCfg(), &kafka.NoopPublisher{})
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestBFFService_Login_HappyPath(t *testing.T) {
	store := newMockStore()
	bl := newMockBlacklist()
	h := &mockHydra{
		issueTokensFn: func(_ context.Context, k, d string, _ bool) (*hydra.TokenSet, error) {
			return &hydra.TokenSet{AccessToken: "at", RefreshToken: "rt"}, nil
		},
		validateAccessTokenFn: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return bffGoodClaims("kratos1", "dev1"), nil
		},
	}
	svc := newBFFService(h, store, bl)

	sessionID, err := svc.Login(context.Background(), "kratos1", "dev1", false, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sessionID) != 64 {
		t.Errorf("expected 64-char session ID, got %d chars", len(sessionID))
	}
	// Session must be in store.
	sess, err := store.Get(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("session not stored: %v", err)
	}
	if sess.KratosID != "kratos1" {
		t.Errorf("wrong kratosID in session")
	}
	// Tokens must NOT be returned to caller (only sessionID).
	_ = sess.HydraAccessToken // only accessible server-side
}

func TestBFFService_Login_HydraFailure(t *testing.T) {
	svc := newBFFService(&mockHydra{
		issueTokensFn: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return nil, errors.New("hydra down")
		},
	}, newMockStore(), newMockBlacklist())

	_, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil)
	if err == nil {
		t.Fatal("expected error on Hydra failure")
	}
}

func TestBFFService_ResolveSession_BlacklistedReturnsError(t *testing.T) {
	store := newMockStore()
	bl := newMockBlacklist()
	bl.entries["sess1"] = true

	svc := newBFFService(&mockHydra{}, store, bl)

	_, _, _, err := svc.ResolveSession(context.Background(), "sess1")
	if !errors.Is(err, service.ErrSessionBlacklisted) {
		t.Errorf("expected ErrSessionBlacklisted, got %v", err)
	}
}

func TestBFFService_ResolveSession_MissingSessionReturnsNotFound(t *testing.T) {
	svc := newBFFService(&mockHydra{}, newMockStore(), newMockBlacklist())

	_, _, _, err := svc.ResolveSession(context.Background(), "nonexistent")
	if !errors.Is(err, service.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestBFFService_ResolveSession_TransparentRefresh(t *testing.T) {
	store := newMockStore()
	bl := newMockBlacklist()

	// Session with access token expiring in 30s (within 60s buffer).
	sess := session.BFFSession{
		SessionID:         "sess-refresh",
		KratosID:          "k1",
		DeviceID:          "d1",
		HydraAccessToken:  "old-at",
		HydraRefreshToken: "old-rt",
		AccessTokenExp:    time.Now().Add(30 * time.Second),
		ExpiresAt:         time.Now().Add(7 * 24 * time.Hour),
	}
	store.Create(context.Background(), sess)

	refreshCalled := false
	h := &mockHydra{
		refreshTokenFn: func(_ context.Context, _ string) (*hydra.TokenSet, error) {
			refreshCalled = true
			return &hydra.TokenSet{AccessToken: "new-at", RefreshToken: "new-rt"}, nil
		},
		validateAccessTokenFn: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return bffGoodClaims("k1", "d1"), nil
		},
	}

	svc := newBFFService(h, store, bl)
	token, _, _, err := svc.ResolveSession(context.Background(), "sess-refresh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !refreshCalled {
		t.Error("expected proactive token refresh to be triggered")
	}
	if token != "new-at" {
		t.Errorf("expected new-at, got %s", token)
	}
}

func TestBFFService_Logout_BlacklistsBeforeDelete(t *testing.T) {
	store := newMockStore()
	bl := newMockBlacklist()

	sess := session.BFFSession{
		SessionID:         "sess-logout",
		KratosID:          "k1",
		DeviceID:          "d1",
		HydraRefreshToken: "rt",
		ExpiresAt:         time.Now().Add(time.Hour),
	}
	store.Create(context.Background(), sess)

	h := &mockHydra{
		revokeTokenFn: func(_ context.Context, _ string) error { return nil },
	}

	svc := newBFFService(h, store, bl)
	if err := svc.Logout(context.Background(), "sess-logout"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bl.entries["sess-logout"] {
		t.Error("session was not blacklisted")
	}
	if _, err := store.Get(context.Background(), "sess-logout"); !errors.Is(err, session.ErrNotFound) {
		t.Error("session was not deleted from store")
	}
}

func TestBFFService_Logout_IdempotentWhenNotFound(t *testing.T) {
	svc := newBFFService(&mockHydra{}, newMockStore(), newMockBlacklist())
	if err := svc.Logout(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("expected nil for missing session, got %v", err)
	}
}

func TestBFFService_LogoutAll_BlacklistsAllSessions(t *testing.T) {
	store := newMockStore()
	bl := newMockBlacklist()

	for _, id := range []string{"s1", "s2", "s3"} {
		store.Create(context.Background(), session.BFFSession{
			SessionID: id, KratosID: "k1", DeviceID: "d" + id,
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}

	h := &mockHydra{
		revokeAllFn: func(_ context.Context, _ string) error { return nil },
	}

	svc := newBFFService(h, store, bl)
	if err := svc.LogoutAll(context.Background(), "s1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, id := range []string{"s1", "s2", "s3"} {
		if !bl.entries[id] {
			t.Errorf("session %s was not blacklisted", id)
		}
	}
}

func TestBFFService_WhoAmI_BlacklistedSession(t *testing.T) {
	bl := newMockBlacklist()
	bl.entries["sess-bl"] = true

	svc := newBFFService(&mockHydra{}, newMockStore(), bl)
	_, _, err := svc.WhoAmI(context.Background(), "sess-bl")
	if !errors.Is(err, service.ErrSessionBlacklisted) {
		t.Errorf("expected ErrSessionBlacklisted, got %v", err)
	}
}

func TestBFFService_ResolveSession_HappyPath_NoRefreshNeeded(t *testing.T) {
	store := newMockStore()
	bl := newMockBlacklist()

	sess := session.BFFSession{
		SessionID:        "good-sess",
		KratosID:         "k1",
		DeviceID:         "d1",
		HydraAccessToken: "valid-at",
		AccessTokenExp:   time.Now().Add(10 * time.Minute), // well within buffer
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
	}
	store.Create(context.Background(), sess)

	svc := newBFFService(&mockHydra{}, store, bl)
	token, kratosID, deviceID, err := svc.ResolveSession(context.Background(), "good-sess")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "valid-at" {
		t.Errorf("expected valid-at, got %s", token)
	}
	if kratosID != "k1" || deviceID != "d1" {
		t.Errorf("unexpected identity: %s/%s", kratosID, deviceID)
	}
}

func TestBFFService_ResolveSession_RefreshLockLost_ReReadsSession(t *testing.T) {
	store := &lockLosingStore{mockSessionStore: newMockStore()}
	bl := newMockBlacklist()

	// Pre-populate with a nearly-expired access token.
	sess := session.BFFSession{
		SessionID:         "lock-sess",
		KratosID:          "k1",
		DeviceID:          "d1",
		HydraAccessToken:  "already-refreshed-at",
		HydraRefreshToken: "rt",
		AccessTokenExp:    time.Now().Add(30 * time.Second), // within 60s buffer
		ExpiresAt:         time.Now().Add(7 * 24 * time.Hour),
	}
	store.Create(context.Background(), sess)

	// Lock always loses — simulates another goroutine holding the lock.
	store.lockAlwaysFails = true

	svc := newBFFService(&mockHydra{}, store, bl)
	token, _, _, err := svc.ResolveSession(context.Background(), "lock-sess")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still return the token (from re-read).
	if token == "" {
		t.Error("expected non-empty token from re-read after lock loss")
	}
}

func TestBFFService_WhoAmI_HappyPath(t *testing.T) {
	store := newMockStore()
	store.Create(context.Background(), session.BFFSession{
		SessionID: "whoami-sess",
		KratosID:  "user1",
		DeviceID:  "device1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	svc := newBFFService(&mockHydra{}, store, newMockBlacklist())
	kratosID, deviceID, err := svc.WhoAmI(context.Background(), "whoami-sess")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kratosID != "user1" || deviceID != "device1" {
		t.Errorf("unexpected identity: %s/%s", kratosID, deviceID)
	}
}

func TestBFFService_WhoAmI_NotFound(t *testing.T) {
	svc := newBFFService(&mockHydra{}, newMockStore(), newMockBlacklist())
	_, _, err := svc.WhoAmI(context.Background(), "missing")
	if !errors.Is(err, service.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestBFFService_LogoutAll_Idempotent(t *testing.T) {
	svc := newBFFService(&mockHydra{}, newMockStore(), newMockBlacklist())
	if err := svc.LogoutAll(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("expected nil for missing session, got %v", err)
	}
}

func TestBFFService_Logout_BlacklistFailure_ReturnsError(t *testing.T) {
	store := newMockStore()
	store.Create(context.Background(), session.BFFSession{
		SessionID: "bl-fail-sess",
		KratosID:  "k1",
		DeviceID:  "d1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	bl := &failingBlacklist{}
	svc := newBFFService(&mockHydra{}, store, bl)

	err := svc.Logout(context.Background(), "bl-fail-sess")
	if err == nil {
		t.Error("expected error when blacklist.Add fails")
	}
}

// ── additional mock helpers ───────────────────────────────────────────────────

// lockLosingStore simulates losing the refresh lock (another goroutine holds it).
type lockLosingStore struct {
	*mockSessionStore
	lockAlwaysFails bool
}

func (s *lockLosingStore) AcquireRefreshLock(_ context.Context, _ string, _ time.Duration) (bool, error) {
	if s.lockAlwaysFails {
		return false, nil
	}
	return true, nil
}
func (s *lockLosingStore) ReleaseRefreshLock(_ context.Context, _ string) error { return nil }

// failingBlacklist always returns an error from Add.
type failingBlacklist struct{}

func (f *failingBlacklist) Add(_ context.Context, _ string, _ time.Duration) error {
	return fmt.Errorf("blacklist unavailable")
}
func (f *failingBlacklist) IsBlacklisted(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (f *failingBlacklist) AddBatch(_ context.Context, _ []string, _ time.Duration) error {
	return fmt.Errorf("blacklist unavailable")
}

func TestBFFService_Login_ValidateTokenFailure_ReturnsError(t *testing.T) {
	h := &mockHydra{
		issueTokensFn: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return &hydra.TokenSet{AccessToken: "at", RefreshToken: "rt"}, nil
		},
		validateAccessTokenFn: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return nil, errors.New("invalid token")
		},
	}
	svc := newBFFService(h, newMockStore(), newMockBlacklist())
	_, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil)
	if err == nil {
		t.Fatal("expected error when ValidateAccessToken fails")
	}
}

func TestBFFService_ResolveSession_RefreshHydraFailure_ReturnsStalToken(t *testing.T) {
	store := newMockStore()
	bl := newMockBlacklist()

	sess := session.BFFSession{
		SessionID:         "stale-sess",
		KratosID:          "k1",
		DeviceID:          "d1",
		HydraAccessToken:  "stale-at",
		HydraRefreshToken: "expired-rt",
		AccessTokenExp:    time.Now().Add(30 * time.Second), // within buffer
		ExpiresAt:         time.Now().Add(7 * 24 * time.Hour),
	}
	store.Create(context.Background(), sess)

	h := &mockHydra{
		refreshTokenFn: func(_ context.Context, _ string) (*hydra.TokenSet, error) {
			return nil, errors.New("refresh token expired")
		},
	}

	svc := newBFFService(h, store, bl)
	token, _, _, err := svc.ResolveSession(context.Background(), "stale-sess")
	// ResolveSession should NOT return an error when refresh fails (warn path).
	if err != nil {
		t.Fatalf("expected nil error on refresh failure, got %v", err)
	}
	// Returns the stale token so upstream can reject it properly.
	if token != "stale-at" {
		t.Errorf("expected stale-at, got %s", token)
	}
}

func TestBFFService_LogoutAll_RevokeSubjectFailure_ReturnsError(t *testing.T) {
	store := newMockStore()
	store.Create(context.Background(), session.BFFSession{
		SessionID: "revoke-fail-sess",
		KratosID:  "k1",
		DeviceID:  "d1",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	h := &mockHydra{
		revokeAllFn: func(_ context.Context, _ string) error {
			return errors.New("hydra admin unavailable")
		},
	}

	svc := newBFFService(h, store, newMockBlacklist())
	err := svc.LogoutAll(context.Background(), "revoke-fail-sess")
	if err == nil {
		t.Error("expected error when RevokeAllForSubject fails")
	}
}

func TestBFFService_Login_PublishesAuthSessionEvent_WithJTI(t *testing.T) {
	store := newMockStore()
	pub := &mockEventPublisher{}
	h := &mockHydra{
		issueTokensFn: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return &hydra.TokenSet{AccessToken: "at", RefreshToken: "rt"}, nil
		},
		validateAccessTokenFn: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return bffGoodClaims("kratos1", "dev1"), nil
		},
	}
	svc := service.NewBFFService(h, store, newMockBlacklist(), &bffMockRedisRepo{}, &bffMockDeviceSessionRepo{}, testCfg(), pub)

	_, err := svc.Login(context.Background(), "kratos1", "dev1", false, nil, nil)
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
	if ev.KratosID != "kratos1" {
		t.Errorf("KratosID: want kratos1, got %s", ev.KratosID)
	}
	if ev.DeviceID != "dev1" {
		t.Errorf("DeviceID: want dev1, got %s", ev.DeviceID)
	}
	if ev.HydraJTI != "test-jti" {
		t.Errorf("HydraJTI: want test-jti, got %s", ev.HydraJTI)
	}
}

func TestBFFService_Login_NoSynchronousDeviceSessionSave(t *testing.T) {
	saveCalled := false
	repo := &trackingDeviceSessionRepo{onSave: func() { saveCalled = true }}

	h := &mockHydra{
		issueTokensFn: func(_ context.Context, _, _ string, _ bool) (*hydra.TokenSet, error) {
			return &hydra.TokenSet{AccessToken: "at", RefreshToken: "rt"}, nil
		},
		validateAccessTokenFn: func(_ context.Context, _ string) (*hydra.AccessTokenClaims, error) {
			return bffGoodClaims("k1", "d1"), nil
		},
	}
	svc := service.NewBFFService(h, newMockStore(), newMockBlacklist(), &bffMockRedisRepo{}, repo, testCfg(), &kafka.NoopPublisher{})

	if _, err := svc.Login(context.Background(), "k1", "d1", false, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saveCalled {
		t.Error("SaveDeviceSession must not be called synchronously in BFF Login (async via Kafka consumer)")
	}
}

// trackingDeviceSessionRepo lets tests observe SaveDeviceSession calls.
type trackingDeviceSessionRepo struct {
	bffMockDeviceSessionRepo
	onSave func()
}

func (r *trackingDeviceSessionRepo) SaveDeviceSession(_ context.Context, _ *domain.DeviceSession) error {
	if r.onSave != nil {
		r.onSave()
	}
	return nil
}

