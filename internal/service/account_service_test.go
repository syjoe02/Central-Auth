package service_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"central-auth/internal/domain"
	kratosclient "central-auth/internal/kratos"
	"central-auth/internal/repository"
	"central-auth/internal/service"
	"central-auth/internal/session"
)

// accountMockKratos is a minimal Kratos mock for AccountService tests.
type accountMockKratos struct {
	getIdentityFullFn func(ctx context.Context, id string) (*kratosclient.IdentityFull, error)
}

func (m *accountMockKratos) GetIdentity(_ context.Context, _ string) (*kratosclient.Identity, error) {
	return nil, nil
}
func (m *accountMockKratos) GetIdentityByEmail(_ context.Context, _ string) (*kratosclient.Identity, error) {
	return nil, nil
}
func (m *accountMockKratos) GetIdentityFull(ctx context.Context, id string) (*kratosclient.IdentityFull, error) {
	return m.getIdentityFullFn(ctx, id)
}
func (m *accountMockKratos) DeleteSessions(_ context.Context, _ string) error { return nil }
func (m *accountMockKratos) CreateIdentity(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (m *accountMockKratos) GetSessionIDByToken(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (m *accountMockKratos) DeleteSession(_ context.Context, _ string) error { return nil }

var _ kratosclient.ClientI = (*accountMockKratos)(nil)

// accountMockBFF is a minimal BFF service mock for AccountService tests.
// Implements all methods of BFFServiceI.
type accountMockBFF struct {
	whoAmIFn func(ctx context.Context, sessionID string) (string, string, error)
	logoutFn func(ctx context.Context, sessionID string) error
}

func (m *accountMockBFF) Login(_ context.Context, _, _ string, _ bool, _ string, _, _ *string) (string, error) {
	return "", nil
}
func (m *accountMockBFF) Logout(ctx context.Context, id string) error {
	if m.logoutFn != nil {
		return m.logoutFn(ctx, id)
	}
	return nil
}
func (m *accountMockBFF) LogoutAll(_ context.Context, _ string) error { return nil }
func (m *accountMockBFF) ResolveSession(_ context.Context, _ string) (string, string, string, error) {
	return "", "", "", nil
}
func (m *accountMockBFF) WhoAmI(ctx context.Context, sessionID string) (string, string, error) {
	if m.whoAmIFn != nil {
		return m.whoAmIFn(ctx, sessionID)
	}
	return "", "", nil
}

var _ service.BFFServiceI = (*accountMockBFF)(nil)

// accountMockStore holds BFF sessions for testing.
// Implements all methods of session.Store.
type accountMockStore struct {
	sessions []session.BFFSession
}

func (m *accountMockStore) Create(_ context.Context, _ session.BFFSession) error { return nil }
func (m *accountMockStore) Get(_ context.Context, _ string) (session.BFFSession, error) {
	return session.BFFSession{}, session.ErrNotFound
}
func (m *accountMockStore) Update(_ context.Context, _ session.BFFSession) error  { return nil }
func (m *accountMockStore) Delete(_ context.Context, _ string) error              { return nil }
func (m *accountMockStore) GetAllForUser(_ context.Context, _ string) ([]session.BFFSession, error) {
	return m.sessions, nil
}
func (m *accountMockStore) DeleteAllForUser(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (m *accountMockStore) AcquireRefreshLock(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return false, nil
}
func (m *accountMockStore) ReleaseRefreshLock(_ context.Context, _ string) error { return nil }

var _ session.Store = (*accountMockStore)(nil)

// accountMockDeviceRepo mocks DeviceSessionRepository.
type accountMockDeviceRepo struct {
	sessions []domain.DeviceSession
}

func (m *accountMockDeviceRepo) SaveDeviceSession(_ context.Context, _ *domain.DeviceSession) error {
	return nil
}
func (m *accountMockDeviceRepo) UpdateLastUsedAt(_ context.Context, _, _ string) error { return nil }
func (m *accountMockDeviceRepo) RevokeDevice(_ context.Context, _, _ string) error     { return nil }
func (m *accountMockDeviceRepo) RevokeAllDevices(_ context.Context, _ string) error    { return nil }
func (m *accountMockDeviceRepo) GetDeviceSessions(_ context.Context, _ string) ([]domain.DeviceSession, error) {
	return m.sessions, nil
}
func (m *accountMockDeviceRepo) CountActiveDevices(_ context.Context, _ string) (int, error) {
	return 0, nil
}

var _ repository.DeviceSessionRepository = (*accountMockDeviceRepo)(nil)

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestAccountService_GetMe_GoogleProvider(t *testing.T) {
	traitsJSON, _ := json.Marshal(map[string]any{
		"email": "alice@example.com",
		"name":  map[string]any{"first": "Alice"},
	})
	kratosMock := &accountMockKratos{
		getIdentityFullFn: func(_ context.Context, _ string) (*kratosclient.IdentityFull, error) {
			return &kratosclient.IdentityFull{
				Identity: kratosclient.Identity{
					ID:     "k1",
					Traits: traitsJSON,
				},
				Credentials: map[string]json.RawMessage{
					"oidc": json.RawMessage(`{}`),
				},
			}, nil
		},
	}
	bffMock := &accountMockBFF{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "k1", "d1", nil
		},
	}

	svc := service.NewAccountService(bffMock, kratosMock, &accountMockStore{}, nil)
	me, err := svc.GetMe(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if me.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", me.Email)
	}
	if me.Name != "Alice" {
		t.Errorf("name = %q, want Alice", me.Name)
	}
	if me.LoginProvider != "Google" {
		t.Errorf("loginProvider = %q, want Google", me.LoginProvider)
	}
}

func TestAccountService_GetMe_PasswordProvider(t *testing.T) {
	traitsJSON, _ := json.Marshal(map[string]any{"email": "bob@example.com"})
	kratosMock := &accountMockKratos{
		getIdentityFullFn: func(_ context.Context, _ string) (*kratosclient.IdentityFull, error) {
			return &kratosclient.IdentityFull{
				Identity: kratosclient.Identity{Traits: traitsJSON},
				Credentials: map[string]json.RawMessage{
					"password": json.RawMessage(`{}`),
				},
			}, nil
		},
	}
	bffMock := &accountMockBFF{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "k2", "d2", nil
		},
	}

	svc := service.NewAccountService(bffMock, kratosMock, &accountMockStore{}, nil)
	me, err := svc.GetMe(context.Background(), "session-2")
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if me.LoginProvider != "Password" {
		t.Errorf("loginProvider = %q, want Password", me.LoginProvider)
	}
}

func TestAccountService_LogoutDevices_OnlyRevokesOwnedDevices(t *testing.T) {
	revokedSessions := []string{}
	bffMock := &accountMockBFF{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "kratos-owner", "current-device", nil
		},
		logoutFn: func(_ context.Context, sid string) error {
			revokedSessions = append(revokedSessions, sid)
			return nil
		},
	}
	store := &accountMockStore{
		sessions: []session.BFFSession{
			{SessionID: "sess-A", KratosID: "kratos-owner", DeviceID: "device-A"},
			{SessionID: "sess-B", KratosID: "kratos-owner", DeviceID: "device-B"},
		},
	}

	svc := service.NewAccountService(bffMock, nil, store, nil)
	// Request to revoke device-A and a foreign device-X (not in user's sessions).
	err := svc.LogoutDevices(context.Background(), "current-session", []string{"device-A", "device-X"})
	if err != nil {
		t.Fatalf("LogoutDevices: %v", err)
	}

	if len(revokedSessions) != 1 || revokedSessions[0] != "sess-A" {
		t.Errorf("revoked sessions = %v, want [sess-A]", revokedSessions)
	}
}

func TestAccountService_LogoutDevices_CannotRevokeCurrentDevice(t *testing.T) {
	revokedSessions := []string{}
	bffMock := &accountMockBFF{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "k1", "current-device", nil
		},
		logoutFn: func(_ context.Context, sid string) error {
			revokedSessions = append(revokedSessions, sid)
			return nil
		},
	}
	store := &accountMockStore{
		sessions: []session.BFFSession{
			{SessionID: "sess-current", KratosID: "k1", DeviceID: "current-device"},
			{SessionID: "sess-other", KratosID: "k1", DeviceID: "other-device"},
		},
	}

	svc := service.NewAccountService(bffMock, nil, store, nil)
	// Try to revoke both — current device must be protected.
	err := svc.LogoutDevices(context.Background(), "current-session", []string{"current-device", "other-device"})
	if err != nil {
		t.Fatalf("LogoutDevices: %v", err)
	}

	if len(revokedSessions) != 1 || revokedSessions[0] != "sess-other" {
		t.Errorf("revoked sessions = %v, want [sess-other]", revokedSessions)
	}
}

func TestAccountService_LogoutOtherDevices_KeepsCurrentDevice(t *testing.T) {
	revokedSessions := []string{}
	bffMock := &accountMockBFF{
		whoAmIFn: func(_ context.Context, _ string) (string, string, error) {
			return "k1", "current-device", nil
		},
		logoutFn: func(_ context.Context, sid string) error {
			revokedSessions = append(revokedSessions, sid)
			return nil
		},
	}
	store := &accountMockStore{
		sessions: []session.BFFSession{
			{SessionID: "sess-current", KratosID: "k1", DeviceID: "current-device"},
			{SessionID: "sess-phone", KratosID: "k1", DeviceID: "phone-device"},
			{SessionID: "sess-tablet", KratosID: "k1", DeviceID: "tablet-device"},
		},
	}

	svc := service.NewAccountService(bffMock, nil, store, nil)
	err := svc.LogoutOtherDevices(context.Background(), "current-session")
	if err != nil {
		t.Fatalf("LogoutOtherDevices: %v", err)
	}

	if len(revokedSessions) != 2 {
		t.Errorf("expected 2 revocations, got %d: %v", len(revokedSessions), revokedSessions)
	}
	for _, sid := range revokedSessions {
		if sid == "sess-current" {
			t.Error("current session must not be revoked")
		}
	}
}
