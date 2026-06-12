package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	"central-auth/internal/blacklist"
	"central-auth/internal/config"
	"central-auth/internal/hydra"
	kafkapkg "central-auth/internal/kafka"
	"central-auth/internal/metrics"
	"central-auth/internal/repository"
	"central-auth/internal/resilience"
	"central-auth/internal/session"
)

// ErrSessionBlacklisted is returned when a session has been explicitly revoked.
var ErrSessionBlacklisted = errors.New("session has been revoked")

// ErrSessionNotFound is returned when the session cookie maps to no active session.
var ErrSessionNotFound = errors.New("session not found or expired")

// BFFServiceI defines the business logic for the BFF session layer.
// Implementations are responsible for:
//   - Issuing opaque sessionIDs (not tokens) to callers.
//   - Storing Hydra tokens server-side and transparently refreshing them.
//   - Fail-closed blacklist checks on every request.
type BFFServiceI interface {
	Login(ctx context.Context, kratosID, deviceID string, rememberMe bool, userAgent, ip *string) (sessionID string, err error)
	Logout(ctx context.Context, sessionID string) error
	LogoutAll(ctx context.Context, sessionID string) error
	// ResolveSession validates the session, checks the blacklist, refreshes the
	// Hydra access token if near expiry, and returns it for upstream forwarding.
	ResolveSession(ctx context.Context, sessionID string) (hydraAccessToken, kratosID, deviceID string, err error)
	WhoAmI(ctx context.Context, sessionID string) (kratosID, deviceID string, err error)
}

// BFFService implements BFFServiceI.
type BFFService struct {
	hydra             hydra.ClientI
	sessionStore      session.Store
	blacklist         blacklist.Blacklist
	redisRepo         repository.RedisRepo
	deviceSessionRepo repository.DeviceSessionRepository
	cfg               config.BFFConfig
	publisher         kafkapkg.EventPublisher
}

// NewBFFService constructs a BFFService with all required dependencies.
// publisher receives AuthSessionEvents after each successful BFF login.
// Pass &kafka.NoopPublisher{} in tests or when Kafka is unavailable.
func NewBFFService(
	hydraClient hydra.ClientI,
	store session.Store,
	bl blacklist.Blacklist,
	redisRepo repository.RedisRepo,
	deviceSessionRepo repository.DeviceSessionRepository,
	cfg config.BFFConfig,
	publisher kafkapkg.EventPublisher,
) *BFFService {
	return &BFFService{
		hydra:             hydraClient,
		sessionStore:      store,
		blacklist:         bl,
		redisRepo:         redisRepo,
		deviceSessionRepo: deviceSessionRepo,
		cfg:               cfg,
		publisher:         publisher,
	}
}

// Login issues Hydra tokens, stores them server-side, and returns an opaque sessionID.
// The sessionID is the only credential returned to the caller; it is stored in an
// HttpOnly cookie. Hydra tokens are never returned to the browser.
func (s *BFFService) Login(
	ctx context.Context,
	kratosID, deviceID string,
	rememberMe bool,
	userAgent, ip *string,
) (string, error) {
	log.Printf("[BFF] Login kratosID=%s device=%s", kratosID, deviceID)

	tokens, err := s.hydra.IssueTokens(ctx, kratosID, deviceID, rememberMe)
	if err != nil {
		log.Printf("[BFF] Login IssueTokens error kratosID=%s: %v", kratosID, err)
		return "", fmt.Errorf("bff login: issue tokens: %w", err)
	}

	// ValidateAccessToken is fatal here (unlike OryAuthService.Login where it is
	// non-fatal). The BFF path requires claims.ID (JTI) for AuthSessionEvent and
	// claims.ExpiresAt to populate BFFSession.AccessTokenExp. Without these the
	// session cannot be constructed correctly, so we fail the login rather than
	// silently issuing a session with a zero expiry or missing JTI correlation.
	claims, err := s.hydra.ValidateAccessToken(ctx, tokens.AccessToken)
	if err != nil {
		return "", fmt.Errorf("bff login: parse access token: %w", err)
	}

	sessionID, err := randomSessionID()
	if err != nil {
		return "", fmt.Errorf("bff login: generate session id: %w", err)
	}

	now := time.Now()
	refreshTTL := RefreshTTLShort
	if rememberMe {
		refreshTTL = RefreshTTLLong
	}

	var accessExp time.Time
	if claims.ExpiresAt != nil {
		accessExp = claims.ExpiresAt.Time
	} else {
		accessExp = now.Add(15 * time.Minute)
	}

	sess := session.BFFSession{
		SessionID:         sessionID,
		KratosID:          kratosID,
		DeviceID:          deviceID,
		HydraAccessToken:  tokens.AccessToken,
		HydraRefreshToken: tokens.RefreshToken,
		AccessTokenExp:    accessExp,
		CreatedAt:         now,
		ExpiresAt:         now.Add(refreshTTL),
	}

	if err := s.sessionStore.Create(ctx, sess); err != nil {
		return "", fmt.Errorf("bff login: store session: %w", err)
	}

	metrics.BFFSessionsCreated.Inc()

	if err := s.redisRepo.SaveLogin(ctx, kratosID, deviceID, tokens.RefreshToken, refreshTTL); err != nil {
		log.Printf("[WARN] bff login: Redis SaveLogin failed (non-fatal): %v", err)
	}

	// claims.ID is the JTI from jwt.RegisteredClaims — already parsed above.
	// Publish non-blocking; the DeviceSessionConsumer persists to device_sessions.
	s.publisher.PublishAuthSession(kafkapkg.AuthSessionEvent{
		EventType: "auth.session.created",
		KratosID:  kratosID,
		DeviceID:  deviceID,
		HydraJTI:  claims.ID,
		IPAddress: derefStr(ip),
		UserAgent: derefStr(userAgent),
		Timestamp: now.UTC().Format(time.RFC3339Nano),
	})

	log.Printf("[BFF] Login success kratosID=%s device=%s", kratosID, deviceID)
	return sessionID, nil
}

// ResolveSession is the hot-path called on every proxied request.
// Order of operations:
//  1. Blacklist check (fail-closed)
//  2. Session lookup
//  3. Proactive Hydra access token refresh if within the configured buffer window
//  4. Return the (possibly refreshed) Hydra access token
func (s *BFFService) ResolveSession(ctx context.Context, sessionID string) (string, string, string, error) {
	blacklisted, err := s.blacklist.IsBlacklisted(ctx, sessionID)
	if err != nil {
		return "", "", "", fmt.Errorf("bff resolve: blacklist check: %w", err)
	}
	if blacklisted {
		metrics.BFFBlacklistChecks.WithLabelValues("hit").Inc()
		return "", "", "", ErrSessionBlacklisted
	}
	metrics.BFFBlacklistChecks.WithLabelValues("miss").Inc()

	sess, err := s.sessionStore.Get(ctx, sessionID)
	if errors.Is(err, session.ErrNotFound) {
		return "", "", "", ErrSessionNotFound
	}
	if err != nil {
		return "", "", "", fmt.Errorf("bff resolve: get session: %w", err)
	}

	if time.Until(sess.AccessTokenExp) < s.cfg.AccessTokenRefreshBuffer {
		refreshed, refreshErr := s.doRefresh(ctx, sess)
		if refreshErr != nil {
			log.Printf("[WARN] bff resolve: transparent refresh failed, returning stale token: %v", refreshErr)
			metrics.BFFTokenRefreshes.WithLabelValues("error").Inc()
		} else {
			sess = refreshed
			metrics.BFFTokenRefreshes.WithLabelValues("ok").Inc()
		}
	}

	return sess.HydraAccessToken, sess.KratosID, sess.DeviceID, nil
}

// doRefresh rotates Hydra tokens for the session under a short distributed lock,
// preventing concurrent goroutines from triggering duplicate refresh calls.
func (s *BFFService) doRefresh(ctx context.Context, sess session.BFFSession) (session.BFFSession, error) {
	const lockTTL = 5 * time.Second

	acquired, err := s.sessionStore.AcquireRefreshLock(ctx, sess.SessionID, lockTTL)
	if err != nil {
		return sess, fmt.Errorf("bff refresh: acquire lock: %w", err)
	}
	if !acquired {
		// Security fix F-5: another goroutine won the lock and is actively refreshing.
		// Wait briefly (up to lockTTL / 2) for the winner to commit the new tokens,
		// then re-read. This closes the TOCTOU window where the loser reads stale tokens
		// before the winner has finished writing.
		const pollInterval = 250 * time.Millisecond
		const maxWait = lockTTL / 2
		deadline := time.Now().Add(maxWait)
		for time.Now().Before(deadline) {
			updated, err := s.sessionStore.Get(ctx, sess.SessionID)
			if err == nil && updated.AccessTokenExp.After(sess.AccessTokenExp) {
				// Winner has written the new tokens.
				return updated, nil
			}
			select {
			case <-ctx.Done():
				return sess, ctx.Err()
			case <-time.After(pollInterval):
			}
		}
		// Timed out waiting — return whatever is in the store now.
		updated, err := s.sessionStore.Get(ctx, sess.SessionID)
		if err != nil {
			return sess, nil // Return original; upstream will reject it if truly expired.
		}
		return updated, nil
	}
	defer s.sessionStore.ReleaseRefreshLock(ctx, sess.SessionID) //nolint:errcheck

	tokens, err := s.hydra.RefreshToken(ctx, sess.HydraRefreshToken)
	if err != nil {
		return sess, fmt.Errorf("bff refresh: hydra refresh: %w", err)
	}

	claims, err := s.hydra.ValidateAccessToken(ctx, tokens.AccessToken)
	if err != nil {
		return sess, fmt.Errorf("bff refresh: parse new access token: %w", err)
	}

	var newExp time.Time
	if claims.ExpiresAt != nil {
		newExp = claims.ExpiresAt.Time
	} else {
		newExp = time.Now().Add(15 * time.Minute)
	}

	sess.HydraAccessToken = tokens.AccessToken
	sess.HydraRefreshToken = tokens.RefreshToken
	sess.AccessTokenExp = newExp

	if err := s.sessionStore.Update(ctx, sess); err != nil {
		return sess, fmt.Errorf("bff refresh: update session: %w", err)
	}

	if err := s.redisRepo.RotateRefreshToken(ctx, sess.KratosID, sess.DeviceID, tokens.RefreshToken, RefreshTTLLong); err != nil {
		log.Printf("[WARN] bff refresh: Redis rotate failed (non-fatal): %v", err)
	}
	if err := s.deviceSessionRepo.UpdateLastUsedAt(ctx, sess.KratosID, sess.DeviceID); err != nil {
		log.Printf("[WARN] bff refresh: Postgres UpdateLastUsedAt failed (non-fatal): %v", err)
	}

	return sess, nil
}

// Logout revokes a single session.
// CRITICAL: blacklist is written BEFORE session deletion so there is no
// window where a concurrent request sees the session deleted but not yet blacklisted.
func (s *BFFService) Logout(ctx context.Context, sessionID string) error {
	log.Printf("[BFF] Logout sessionID=%s", truncateSessionID(sessionID))

	sess, err := s.sessionStore.Get(ctx, sessionID)
	if errors.Is(err, session.ErrNotFound) {
		return nil // idempotent
	}
	if err != nil {
		return fmt.Errorf("bff logout: get session: %w", err)
	}

	// Blacklist-first: abort if this fails to prevent partial revocation.
	// ErrRedisUnavailable means the session was written to PostgreSQL + L1 cache
	// by the resilient blacklist — the session is still revoked, so logout may proceed.
	if err := s.blacklist.Add(ctx, sessionID, time.Until(sess.ExpiresAt)); err != nil {
		if !errors.Is(err, resilience.ErrRedisUnavailable) {
			return fmt.Errorf("bff logout: blacklist session: %w", err)
		}
		log.Printf("[WARN] bff logout: Redis unavailable, session blacklisted via PG fallback: %v", err)
	}

	if err := s.hydra.RevokeToken(ctx, sess.HydraRefreshToken); err != nil {
		log.Printf("[WARN] bff logout: Hydra RevokeToken failed (non-fatal): %v", err)
	}

	if err := s.sessionStore.Delete(ctx, sessionID); err != nil {
		log.Printf("[WARN] bff logout: session delete failed (non-fatal): %v", err)
	}

	metrics.BFFSessionsDestroyed.Inc()

	if err := s.redisRepo.LogoutDevice(ctx, sess.KratosID, sess.DeviceID); err != nil {
		log.Printf("[WARN] bff logout: Redis cleanup failed (non-fatal): %v", err)
	}
	if err := s.deviceSessionRepo.RevokeDevice(ctx, sess.KratosID, sess.DeviceID); err != nil {
		log.Printf("[WARN] bff logout: Postgres revoke failed (non-fatal): %v", err)
	}

	log.Printf("[BFF] Logout success sessionID=%s kratosID=%s", truncateSessionID(sessionID), sess.KratosID)
	return nil
}

// LogoutAll revokes all sessions for the user identified by the given sessionID.
// Hydra token revocation happens before blacklisting to ensure no new tokens can
// be issued while we are in the middle of the operation.
func (s *BFFService) LogoutAll(ctx context.Context, sessionID string) error {
	log.Printf("[BFF] LogoutAll sessionID=%s", truncateSessionID(sessionID))

	sess, err := s.sessionStore.Get(ctx, sessionID)
	if errors.Is(err, session.ErrNotFound) {
		return nil // idempotent
	}
	if err != nil {
		return fmt.Errorf("bff logout-all: get session: %w", err)
	}

	kratosID := sess.KratosID

	allSessions, err := s.sessionStore.GetAllForUser(ctx, kratosID)
	if err != nil {
		return fmt.Errorf("bff logout-all: get all sessions: %w", err)
	}

	// Blacklist-first: same invariant as Logout — must succeed before any revocation
	// so that concurrent in-flight requests are blocked immediately.
	maxTTL := time.Until(sess.ExpiresAt)
	sessionIDs := make([]string, 0, len(allSessions))
	for _, s2 := range allSessions {
		sessionIDs = append(sessionIDs, s2.SessionID)
		if remaining := time.Until(s2.ExpiresAt); remaining > maxTTL {
			maxTTL = remaining
		}
	}

	if err := s.blacklist.AddBatch(ctx, sessionIDs, maxTTL); err != nil {
		if !errors.Is(err, resilience.ErrRedisUnavailable) {
			return fmt.Errorf("bff logout-all: blacklist sessions: %w", err)
		}
		log.Printf("[WARN] bff logout-all: Redis unavailable, sessions blacklisted via PG fallback: %v", err)
	}

	if err := s.hydra.RevokeAllForSubject(ctx, kratosID); err != nil {
		log.Printf("[ERROR] bff logout-all: RevokeAllForSubject failed: %v", err)
		return fmt.Errorf("bff logout-all: revoke tokens: %w", err)
	}

	if _, err := s.sessionStore.DeleteAllForUser(ctx, kratosID); err != nil {
		log.Printf("[WARN] bff logout-all: delete sessions failed (non-fatal): %v", err)
	}

	metrics.BFFSessionsDestroyed.Add(float64(len(sessionIDs)))

	if err := s.redisRepo.LogoutAll(ctx, kratosID); err != nil {
		log.Printf("[WARN] bff logout-all: Redis cleanup failed (non-fatal): %v", err)
	}
	if err := s.deviceSessionRepo.RevokeAllDevices(ctx, kratosID); err != nil {
		log.Printf("[WARN] bff logout-all: Postgres revoke failed (non-fatal): %v", err)
	}

	log.Printf("[BFF] LogoutAll success kratosID=%s sessions=%d", kratosID, len(sessionIDs))
	return nil
}

// WhoAmI returns identity metadata for the given session without forwarding a token upstream.
func (s *BFFService) WhoAmI(ctx context.Context, sessionID string) (string, string, error) {
	blacklisted, err := s.blacklist.IsBlacklisted(ctx, sessionID)
	if err != nil {
		return "", "", fmt.Errorf("bff whoami: blacklist check: %w", err)
	}
	if blacklisted {
		return "", "", ErrSessionBlacklisted
	}

	sess, err := s.sessionStore.Get(ctx, sessionID)
	if errors.Is(err, session.ErrNotFound) {
		return "", "", ErrSessionNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("bff whoami: get session: %w", err)
	}
	return sess.KratosID, sess.DeviceID, nil
}

// randomSessionID generates a 64-character hex session ID from crypto/rand.
func randomSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random session id: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}

// truncateSessionID returns only the first 8 hex characters of a sessionID for
// use in log messages — enough to correlate logs without leaking the full token.
// Security fix F-11: full 64-char sessionIDs in logs are effectively plaintext
// session tokens that could be replayed by log-access attackers.
func truncateSessionID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// compile-time interface check
var _ BFFServiceI = (*BFFService)(nil)
