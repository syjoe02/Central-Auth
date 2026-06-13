package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	kratosclient "central-auth/internal/kratos"
	"central-auth/internal/model"
	"central-auth/internal/repository"
	"central-auth/internal/session"
	"central-auth/internal/uaparser"
)

// AccountServiceI defines account and session management operations.
// All methods require a valid BFF sessionID (from the __session cookie).
type AccountServiceI interface {
	GetMe(ctx context.Context, sessionID string) (*model.AccountMeResponse, error)
	GetSessions(ctx context.Context, sessionID string) (*model.SessionsResponse, error)
	LogoutDevices(ctx context.Context, sessionID string, deviceIDs []string) error
	LogoutOtherDevices(ctx context.Context, sessionID string) error
}

type AccountService struct {
	bff               BFFServiceI
	kratosClient      kratosclient.ClientI
	sessionStore      session.Store
	deviceSessionRepo repository.DeviceSessionRepository
}

func NewAccountService(
	bff BFFServiceI,
	kratosClient kratosclient.ClientI,
	store session.Store,
	deviceSessionRepo repository.DeviceSessionRepository,
) *AccountService {
	return &AccountService{
		bff:               bff,
		kratosClient:      kratosClient,
		sessionStore:      store,
		deviceSessionRepo: deviceSessionRepo,
	}
}

func (s *AccountService) GetMe(ctx context.Context, sessionID string) (*model.AccountMeResponse, error) {
	kratosID, _, err := s.bff.WhoAmI(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("account: whoami: %w", err)
	}

	identity, err := s.kratosClient.GetIdentityFull(ctx, kratosID)
	if err != nil {
		return nil, fmt.Errorf("account: get identity: %w", err)
	}

	var traits struct {
		Email string `json:"email"`
		Name  struct {
			First string `json:"first"`
		} `json:"name"`
	}
	if err := json.Unmarshal(identity.Traits, &traits); err != nil {
		return nil, fmt.Errorf("account: parse traits: %w", err)
	}

	provider := "Password"
	if _, ok := identity.Credentials["oidc"]; ok {
		provider = "Google"
	}

	return &model.AccountMeResponse{
		Email:         traits.Email,
		Name:          traits.Name.First,
		LoginProvider: provider,
	}, nil
}

func (s *AccountService) GetSessions(ctx context.Context, sessionID string) (*model.SessionsResponse, error) {
	kratosID, currentDeviceID, err := s.bff.WhoAmI(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("account: whoami: %w", err)
	}

	pgSessions, err := s.deviceSessionRepo.GetDeviceSessions(ctx, kratosID)
	if err != nil {
		return nil, fmt.Errorf("account: get device sessions: %w", err)
	}

	bffSessions, err := s.sessionStore.GetAllForUser(ctx, kratosID)
	if err != nil {
		return nil, fmt.Errorf("account: get all user sessions: %w", err)
	}

	activeDevices := make(map[string]struct{}, len(bffSessions))
	for _, bs := range bffSessions {
		activeDevices[bs.DeviceID] = struct{}{}
	}

	var current *model.DeviceInfo
	var others []model.DeviceInfo

	for _, pg := range pgSessions {
		if _, active := activeDevices[pg.DeviceID]; !active {
			continue
		}
		if pg.Revoked {
			continue
		}

		ua := ""
		if pg.UserAgent != nil {
			ua = *pg.UserAgent
		}
		parsed := uaparser.Parse(ua)

		info := model.DeviceInfo{
			DeviceID:   pg.DeviceID,
			Browser:    parsed.Browser,
			OS:         parsed.OS,
			LastUsedAt: pg.LastUsedAt,
			IsCurrent:  pg.DeviceID == currentDeviceID,
		}

		if pg.DeviceID == currentDeviceID {
			current = &info
		} else {
			others = append(others, info)
		}
	}

	if others == nil {
		others = []model.DeviceInfo{}
	}

	return &model.SessionsResponse{
		CurrentDevice: current,
		OtherDevices:  others,
	}, nil
}

func (s *AccountService) LogoutDevices(ctx context.Context, sessionID string, deviceIDs []string) error {
	kratosID, currentDeviceID, err := s.bff.WhoAmI(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("account: whoami: %w", err)
	}

	requested := make(map[string]struct{}, len(deviceIDs))
	for _, id := range deviceIDs {
		if id != currentDeviceID {
			requested[id] = struct{}{}
		}
	}
	// If all requested device IDs were the current device, requested is empty
	// and this is a no-op. This is intentional: callers cannot log out their
	// own current session via this endpoint.

	bffSessions, err := s.sessionStore.GetAllForUser(ctx, kratosID)
	if err != nil {
		return fmt.Errorf("account: get all user sessions: %w", err)
	}

	for _, bs := range bffSessions {
		if _, ok := requested[bs.DeviceID]; !ok {
			continue
		}
		if err := s.bff.Logout(ctx, bs.SessionID); err != nil {
			log.Printf("[WARN] account: logout device %s session %s: %v", bs.DeviceID, bs.SessionID, err)
		}
	}

	return nil
}

func (s *AccountService) LogoutOtherDevices(ctx context.Context, sessionID string) error {
	kratosID, currentDeviceID, err := s.bff.WhoAmI(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("account: whoami: %w", err)
	}

	bffSessions, err := s.sessionStore.GetAllForUser(ctx, kratosID)
	if err != nil {
		return fmt.Errorf("account: get all user sessions: %w", err)
	}

	for _, bs := range bffSessions {
		if bs.DeviceID == currentDeviceID {
			continue
		}
		if err := s.bff.Logout(ctx, bs.SessionID); err != nil {
			log.Printf("[WARN] account: logout other device %s session %s: %v", bs.DeviceID, bs.SessionID, err)
		}
	}

	return nil
}

var _ AccountServiceI = (*AccountService)(nil)
