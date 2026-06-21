package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"central-auth/internal/blacklist"
	"central-auth/internal/hydra"
	kafkapkg "central-auth/internal/kafka"
	"central-auth/internal/kratos"
	"central-auth/internal/repository"
	"central-auth/internal/requestid"
	"central-auth/internal/resilience"
)

const (
	RefreshTTLShort    = time.Hour * 24 * 7  // 7 days (default)
	RefreshTTLLong     = time.Hour * 24 * 30 // 30 days (remember_me)
	accessTokenTTL     = time.Minute * 15    // must match Hydra TTL_ACCESS_TOKEN
	blacklistSyncExtra = time.Minute * 5     // grace buffer added on top of accessTokenTTL
)

// ErrInvalidToken is returned by the service for token errors that should map
// to HTTP 401 on the caller side (bad token, expired, wrong type).
var ErrInvalidToken = errors.New("invalid or expired token")

// ErrEmailConflict is returned by Signup when the email is already registered.
var ErrEmailConflict = errors.New("email already registered")

// ErrInvalidCredentials is returned by GoogleLogin when no identity with the given email exists.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrTokenRevoked is returned by VerifyToken when the token's device or user
// has been explicitly blacklisted via Logout / LogoutAll.
var ErrTokenRevoked = errors.New("token revoked")

// VerifyResult holds the validated claims extracted from a Hydra access token.
type VerifyResult struct {
	KratosID  string
	DeviceID  string
	ExpiresAt int64
}

// AuthServiceI is the interface that wraps all auth business logic operations.
// It is satisfied by both OryAuthService (real) and InstrumentedAuthService (metrics wrapper).
type AuthServiceI interface {
	// Login issues Hydra tokens for a pre-authenticated Kratos identity.
	// The caller has already verified the user's credentials via Kratos.
	Login(ctx context.Context, kratosID, deviceID string, rememberMe bool, userAgent, ip *string) (accessToken, refreshToken string, err error)

	// Logout revokes the session identified by the given Hydra refresh token.
	Logout(ctx context.Context, refreshToken string) error

	// LogoutAll revokes all sessions for the user identified by the given Hydra refresh token.
	LogoutAll(ctx context.Context, refreshToken string) error

	// Refresh exchanges a Hydra refresh token for a new access+refresh token pair.
	Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)

	// VerifyToken validates a Hydra access token JWT and returns its claims.
	// Fail-closed: any error (invalid signature, expired, JWKS unavailable) returns a non-nil error.
	VerifyToken(ctx context.Context, accessToken string) (*VerifyResult, error)

	// Signup creates a new Kratos identity for the given email (no password credential).
	// The identity is linked to Google OIDC on the user's first Google login.
	// Returns the new Kratos identity UUID. Returns ErrEmailConflict if the email is already registered.
	Signup(ctx context.Context, email string) (kratosID string, err error)

	// GoogleLogin looks up the Kratos identity by email (already verified via OIDC)
	// and issues Hydra tokens. Returns ErrInvalidCredentials if no identity exists.
	GoogleLogin(ctx context.Context, email, deviceID string, rememberMe bool, userAgent, ip *string) (accessToken, refreshToken string, err error)
}

// OryAuthService implements AuthServiceI using Ory Hydra for token management
// and Redis for atomic device-session enforcement.
type OryAuthService struct {
	hydra             hydra.ClientI
	redisRepo         repository.RedisRepo
	deviceSessionRepo repository.DeviceSessionRepository
	kratosClient      kratos.ClientI
	// blacklist is optional. When set, VerifyToken checks device and user
	// revocation keys written by Logout / LogoutAll.
	blacklist blacklist.Blacklist
	// publisher receives AuthSessionEvents after each successful login.
	// Defaults to NoopPublisher so callers that omit WithEventPublisher are safe.
	publisher kafkapkg.EventPublisher
}

// OryAuthServiceOption is a functional option for OryAuthService.
type OryAuthServiceOption func(*OryAuthService)

// WithKratosClient sets the Kratos admin client used by the Signup method.
func WithKratosClient(c kratos.ClientI) OryAuthServiceOption {
	return func(s *OryAuthService) { s.kratosClient = c }
}

// WithEventPublisher attaches a Kafka publisher for AuthSessionEvents.
// When omitted, a NoopPublisher is used and no Kafka messages are produced.
func WithEventPublisher(pub kafkapkg.EventPublisher) OryAuthServiceOption {
	return func(s *OryAuthService) { s.publisher = pub }
}

// WithBlacklist attaches an optional revocation blacklist.
// When set, VerifyToken checks device:{kratosID}:{deviceID} and user:{kratosID}
// before returning claims. Logout / LogoutAll write to those keys.
// Use the ResilientBlacklist wrapper so the check survives Redis outages.
func WithBlacklist(bl blacklist.Blacklist) OryAuthServiceOption {
	return func(s *OryAuthService) { s.blacklist = bl }
}

// NewOryAuthService creates a new OryAuthService.
func NewOryAuthService(
	hydraClient hydra.ClientI,
	redisRepo repository.RedisRepo,
	deviceSessionRepo repository.DeviceSessionRepository,
	opts ...OryAuthServiceOption,
) *OryAuthService {
	s := &OryAuthService{
		hydra:             hydraClient,
		redisRepo:         redisRepo,
		deviceSessionRepo: deviceSessionRepo,
		publisher:         &kafkapkg.NoopPublisher{}, // safe default; overridden by WithEventPublisher
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Login issues Hydra tokens for a Kratos identity.
//
// Flow:
//  1. Programmatic Hydra authorization code flow → access + refresh tokens
//  2. Redis atomic Lua script enforces max-5-device limit (evicts oldest if needed)
//  3. AuthSessionEvent published to Kafka (non-blocking); the DeviceSessionConsumer
//     persists the audit row to device_sessions asynchronously
func (s *OryAuthService) Login(
	ctx context.Context,
	kratosID, deviceID string,
	rememberMe bool,
	userAgent, ip *string,
) (string, string, error) {
	log.Printf("[AUTH] Login start kratosID=%s device=%s", maskID(kratosID), maskID(deviceID))

	tokens, err := s.hydra.IssueTokens(ctx, kratosID, deviceID, rememberMe)
	if err != nil {
		log.Printf("[ERROR] Hydra IssueTokens failed: %+v", err)
		return "", "", fmt.Errorf("login: issue tokens: %w", err)
	}

	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	if err := s.redisRepo.SaveLogin(ctx, kratosID, deviceID, tokens.RefreshToken, refreshTTL); err != nil {
		log.Printf("[ERROR] Redis SaveLogin failed: %+v", err)
		return "", "", fmt.Errorf("login: save session: %w", err)
	}

	// Extract JTI from the access token to include in the audit event.
	// ValidateAccessToken is a local JWT parse (JWKS cache, no network on warm path).
	// Failure is non-fatal: the login still succeeds; the audit event carries an empty JTI.
	jti := ""
	if claims, err := s.hydra.ValidateAccessToken(ctx, tokens.AccessToken); err != nil {
		log.Printf("[WARN] login: parse access token for audit (non-fatal): %v", err)
	} else {
		jti = claims.ID // jwt.RegisteredClaims.ID
	}

	s.publisher.PublishAuthSession(kafkapkg.AuthSessionEvent{
		EventType: "auth.session.created",
		KratosID:  kratosID,
		DeviceID:  deviceID,
		HydraJTI:  jti,
		IPAddress: derefStr(ip),
		UserAgent: derefStr(userAgent),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})

	log.Printf("[AUTH] Login success kratosID=%s device=%s", maskID(kratosID), maskID(deviceID))
	return tokens.AccessToken, tokens.RefreshToken, nil
}

// Logout revokes the session for the device identified by the Hydra refresh token.
//
// Flow:
//  1. Introspect the refresh token via Hydra Admin API → extract kratosID + deviceID
//  2. Revoke the token in Hydra (invalidates associated access tokens too)
//  3. Remove the device from Redis
//  4. Mark the device_sessions row as revoked in Postgres
func (s *OryAuthService) Logout(ctx context.Context, refreshToken string) error {
	rid := requestid.FromContext(ctx)
	log.Printf("[AUTH] [%s] Logout start", rid)

	introspect, err := s.hydra.IntrospectToken(ctx, refreshToken)
	if err != nil {
		log.Printf("[ERROR] [%s] Hydra IntrospectToken failed: %+v", rid, err)
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !introspect.Active {
		return fmt.Errorf("%w: token is inactive", ErrInvalidToken)
	}

	kratosID := introspect.Subject
	deviceID := introspect.DeviceID()
	if kratosID == "" || deviceID == "" {
		log.Printf("[ERROR] [%s] Logout: missing claims kratosID=%s deviceID=%s", rid, maskID(kratosID), maskID(deviceID))
		return fmt.Errorf("%w: missing subject or device_id in token", ErrInvalidToken)
	}

	if err := s.hydra.RevokeToken(ctx, refreshToken); err != nil {
		log.Printf("[ERROR] [%s] Hydra RevokeToken failed: %+v", rid, err)
		return fmt.Errorf("logout: revoke token: %w", err)
	}

	// Blacklist the device key so VerifyToken rejects in-flight access tokens
	// before they expire naturally. Fail-closed: hard errors abort the logout.
	if s.blacklist != nil {
		deviceKey := "device:" + kratosID + ":" + deviceID
		if blErr := s.blacklist.Add(ctx, deviceKey, RefreshTTLLong); blErr != nil {
			if !errors.Is(blErr, resilience.ErrRedisUnavailable) {
				log.Printf("[ERROR] [%s] logout: blacklist device failed kratosID=%s: %v", rid, maskID(kratosID), blErr)
				return fmt.Errorf("logout: blacklist device: %w", blErr)
			}
			log.Printf("[WARN] [%s] logout: blacklist degraded (ErrRedisUnavailable), device written to PG fallback kratosID=%s", rid, maskID(kratosID))
		}
	}

	// Fan-out revocation to downstream services (backendKotlin) via Kafka.
	// ExpiresAt = access token TTL + buffer; downstream services use this to set
	// their Redis TTL instead of a fixed 60s, avoiding premature eviction.
	expiresAt := time.Now().UTC().Add(accessTokenTTL + blacklistSyncExtra)
	s.publisher.PublishBlacklistSync(kafkapkg.BlacklistSyncEvent{
		EventType:   "blacklist.sync",
		TargetType:  "DEVICE",
		TargetValue: kratosID + ":" + deviceID,
		Reason:      "user logout",
		ExpiresAt:   expiresAt.Format(time.RFC3339Nano),
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})

	if err := s.redisRepo.LogoutDevice(ctx, kratosID, deviceID); err != nil {
		log.Printf("[WARN] [%s] logout: Redis cleanup failed (non-fatal): %v", rid, err)
	}

	if err := s.deviceSessionRepo.RevokeDevice(ctx, kratosID, deviceID); err != nil {
		log.Printf("[WARN] [%s] logout: Postgres revoke failed (non-fatal): %v", rid, err)
	}

	log.Printf("[AUTH] [%s] Logout success kratosID=%s device=%s", rid, maskID(kratosID), maskID(deviceID))
	return nil
}

// LogoutAll revokes all sessions for the user identified by the Hydra refresh token.
//
// Flow:
//  1. Introspect the refresh token → extract kratosID
//  2. Hydra Admin API: delete all tokens for the subject
//  3. Redis: remove all device entries
//  4. Postgres: mark all device_sessions rows as revoked
func (s *OryAuthService) LogoutAll(ctx context.Context, refreshToken string) error {
	rid := requestid.FromContext(ctx)
	log.Printf("[AUTH] [%s] LogoutAll start", rid)

	introspect, err := s.hydra.IntrospectToken(ctx, refreshToken)
	if err != nil {
		log.Printf("[ERROR] [%s] Hydra IntrospectToken failed: %+v", rid, err)
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !introspect.Active {
		return fmt.Errorf("%w: token is inactive", ErrInvalidToken)
	}

	kratosID := introspect.Subject
	if kratosID == "" {
		return fmt.Errorf("%w: missing subject in token", ErrInvalidToken)
	}

	if err := s.hydra.RevokeAllForSubject(ctx, kratosID); err != nil {
		log.Printf("[ERROR] [%s] Hydra RevokeAllForSubject failed: %+v", rid, err)
		return fmt.Errorf("logout all: revoke tokens: %w", err)
	}

	// Blacklist the user key so VerifyToken rejects all this user's tokens
	// before they expire naturally.
	if s.blacklist != nil {
		userKey := "user:" + kratosID
		if blErr := s.blacklist.Add(ctx, userKey, RefreshTTLLong); blErr != nil {
			if !errors.Is(blErr, resilience.ErrRedisUnavailable) {
				log.Printf("[ERROR] [%s] logout-all: blacklist user failed kratosID=%s: %v", rid, maskID(kratosID), blErr)
				return fmt.Errorf("logout-all: blacklist user: %w", blErr)
			}
			log.Printf("[WARN] [%s] logout-all: blacklist degraded (ErrRedisUnavailable), user key written to PG fallback kratosID=%s", rid, maskID(kratosID))
		}
	}

	expiresAt := time.Now().UTC().Add(accessTokenTTL + blacklistSyncExtra)
	s.publisher.PublishBlacklistSync(kafkapkg.BlacklistSyncEvent{
		EventType:   "blacklist.sync",
		TargetType:  "USER",
		TargetValue: kratosID,
		Reason:      "user logout-all",
		ExpiresAt:   expiresAt.Format(time.RFC3339Nano),
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})

	if err := s.redisRepo.LogoutAll(ctx, kratosID); err != nil {
		log.Printf("[WARN] [%s] logout-all: Redis cleanup failed (non-fatal): %v", rid, err)
	}

	if err := s.deviceSessionRepo.RevokeAllDevices(ctx, kratosID); err != nil {
		log.Printf("[WARN] [%s] logout-all: Postgres revoke failed (non-fatal): %v", rid, err)
	}

	log.Printf("[AUTH] [%s] LogoutAll success kratosID=%s", rid, maskID(kratosID))
	return nil
}

// Refresh exchanges a Hydra refresh token for a new access+refresh token pair.
//
// Flow:
//  1. Call Hydra token endpoint with grant_type=refresh_token
//  2. Parse the new access token JWT to extract kratosID and deviceID
//  3. Update Redis with the new refresh token (old token is now invalid in Hydra)
//  4. Update device_sessions.last_used_at
func (s *OryAuthService) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	log.Printf("[AUTH] Refresh start")

	tokens, err := s.hydra.RefreshToken(ctx, refreshToken)
	if err != nil {
		log.Printf("[ERROR] Hydra RefreshToken failed: %+v", err)
		return "", "", fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	// Parse the new access token to get kratosID and deviceID for cleanup.
	claims, err := s.hydra.ValidateAccessToken(ctx, tokens.AccessToken)
	if err != nil {
		log.Printf("[ERROR] Parse new access token failed: %+v", err)
		return "", "", fmt.Errorf("refresh: parse new access token: %w", err)
	}

	kratosID := claims.Subject
	deviceID := claims.DeviceID()

	if err := s.redisRepo.RotateRefreshToken(ctx, kratosID, deviceID, tokens.RefreshToken, RefreshTTLLong); err != nil {
		log.Printf("[WARN] refresh: Redis rotate failed (non-fatal): %v", err)
	}

	if err := s.deviceSessionRepo.UpdateLastUsedAt(ctx, kratosID, deviceID); err != nil {
		log.Printf("[WARN] refresh: Postgres update last_used_at failed (non-fatal): %v", err)
	}

	log.Printf("[AUTH] Refresh success kratosID=%s device=%s", maskID(kratosID), maskID(deviceID))
	return tokens.AccessToken, tokens.RefreshToken, nil
}

// VerifyToken validates a Hydra JWT access token locally using JWKS.
// Fail-closed: any error causes the caller to return HTTP 401.
// When a Blacklist is configured, also checks device and user revocation keys.
func (s *OryAuthService) VerifyToken(ctx context.Context, accessToken string) (*VerifyResult, error) {
	rid := requestid.FromContext(ctx)
	claims, err := s.hydra.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	deviceID := claims.DeviceID()
	if claims.Subject == "" || deviceID == "" {
		return nil, errors.New("missing subject or device_id in token")
	}

	if s.blacklist != nil {
		for _, key := range []string{
			"device:" + claims.Subject + ":" + deviceID,
			"user:" + claims.Subject,
		} {
			revoked, blErr := s.blacklist.IsBlacklisted(ctx, key)
			if blErr != nil {
				log.Printf("[ERROR] [%s] verify_token: blacklist check key=%s: %v", rid, key, blErr)
				return nil, fmt.Errorf("%w: blacklist check: %w", ErrTokenRevoked, blErr)
			}
			if revoked {
				log.Printf("[WARN] [%s] verify_token: token revoked key=%s kratosID=%s", rid, key, maskID(claims.Subject))
				return nil, fmt.Errorf("%w: key=%s", ErrTokenRevoked, key)
			}
		}
	}

	var exp int64
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	return &VerifyResult{
		KratosID:  claims.Subject,
		DeviceID:  deviceID,
		ExpiresAt: exp,
	}, nil
}

// maskID truncates an identifier to its first 8 characters for safe log output.
// Full UUIDs (e.g. Kratos identities) must not appear in logs in production.
func maskID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "..."
}

// derefStr safely dereferences a string pointer; returns "" for nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Signup creates a new Kratos identity for the given email with no password credential.
// The identity is linked to Google OIDC automatically on the user's first Google login.
// Returns the Kratos identity UUID on success. Returns ErrEmailConflict if the email is already registered.
func (s *OryAuthService) Signup(ctx context.Context, email string) (string, error) {
	if s.kratosClient == nil {
		return "", fmt.Errorf("signup: Kratos client not configured")
	}
	id, err := s.kratosClient.CreateIdentity(ctx, email)
	if err != nil {
		if errors.Is(err, kratos.ErrEmailConflict) {
			return "", ErrEmailConflict
		}
		log.Printf("[ERROR] Kratos CreateIdentity failed: %v", err)
		return "", fmt.Errorf("signup: create identity: %w", err)
	}
	log.Printf("[AUTH] Signup success kratosID=%s", maskID(id))
	return id, nil
}

// GoogleLogin looks up the Kratos identity by email (already OIDC-verified by Kratos)
// and issues Hydra tokens. Returns ErrInvalidCredentials when no identity with
// that email exists.
func (s *OryAuthService) GoogleLogin(
	ctx context.Context,
	email, deviceID string,
	rememberMe bool,
	userAgent, ip *string,
) (string, string, error) {
	if s.kratosClient == nil {
		return "", "", fmt.Errorf("google_login: Kratos client not configured")
	}
	identity, err := s.kratosClient.GetIdentityByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, kratos.ErrInvalidCredentials) {
			return "", "", ErrInvalidCredentials
		}
		log.Printf("[ERROR] Kratos GetIdentityByEmail failed: %v", err)
		return "", "", fmt.Errorf("google_login: lookup identity: %w", err)
	}
	return s.Login(ctx, identity.ID, deviceID, rememberMe, userAgent, ip)
}

// compile-time interface check
var _ AuthServiceI = (*OryAuthService)(nil)
