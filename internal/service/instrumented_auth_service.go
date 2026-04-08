package service

import (
	"context"
	"time"

	"central-auth/internal/metrics"
)

// InstrumentedAuthService wraps AuthServiceI and records Prometheus metrics
// for each operation without touching any business logic.
type InstrumentedAuthService struct {
	delegate AuthServiceI
}

// NewInstrumentedAuthService wraps the given service with Prometheus instrumentation.
func NewInstrumentedAuthService(delegate AuthServiceI) *InstrumentedAuthService {
	return &InstrumentedAuthService{delegate: delegate}
}

func (s *InstrumentedAuthService) Login(ctx context.Context, kratosID, deviceID string, rememberMe bool, userAgent, ip *string) (string, string, error) {
	start := time.Now()
	access, refresh, err := s.delegate.Login(ctx, kratosID, deviceID, rememberMe, userAgent, ip)
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.AuthOps.WithLabelValues("login", result).Inc()
	metrics.OryOps.WithLabelValues("hydra_issue_tokens").Observe(time.Since(start).Seconds())
	return access, refresh, err
}

func (s *InstrumentedAuthService) Logout(ctx context.Context, refreshToken string) error {
	start := time.Now()
	err := s.delegate.Logout(ctx, refreshToken)
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.AuthOps.WithLabelValues("logout", result).Inc()
	metrics.OryOps.WithLabelValues("hydra_revoke_token").Observe(time.Since(start).Seconds())
	return err
}

func (s *InstrumentedAuthService) LogoutAll(ctx context.Context, refreshToken string) error {
	start := time.Now()
	err := s.delegate.LogoutAll(ctx, refreshToken)
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.AuthOps.WithLabelValues("logout_all", result).Inc()
	metrics.OryOps.WithLabelValues("hydra_revoke_all").Observe(time.Since(start).Seconds())
	return err
}

func (s *InstrumentedAuthService) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	start := time.Now()
	access, refresh, err := s.delegate.Refresh(ctx, refreshToken)
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.AuthOps.WithLabelValues("refresh", result).Inc()
	metrics.OryOps.WithLabelValues("hydra_refresh_token").Observe(time.Since(start).Seconds())
	return access, refresh, err
}

func (s *InstrumentedAuthService) VerifyToken(ctx context.Context, accessToken string) (*VerifyResult, error) {
	start := time.Now()
	result, err := s.delegate.VerifyToken(ctx, accessToken)
	metrics.OryOps.WithLabelValues("hydra_validate_jwt").Observe(time.Since(start).Seconds())
	return result, err
}

func (s *InstrumentedAuthService) LoginWithPassword(ctx context.Context, email, password, deviceID string, rememberMe bool, userAgent, ip *string) (string, string, error) {
	start := time.Now()
	access, refresh, err := s.delegate.LoginWithPassword(ctx, email, password, deviceID, rememberMe, userAgent, ip)
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.AuthOps.WithLabelValues("login_with_password", result).Inc()
	metrics.OryOps.WithLabelValues("kratos_authenticate").Observe(time.Since(start).Seconds())
	return access, refresh, err
}

func (s *InstrumentedAuthService) Signup(ctx context.Context, email, password string) (string, error) {
	start := time.Now()
	id, err := s.delegate.Signup(ctx, email, password)
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.AuthOps.WithLabelValues("signup", result).Inc()
	metrics.OryOps.WithLabelValues("kratos_create_identity").Observe(time.Since(start).Seconds())
	return id, err
}

func (s *InstrumentedAuthService) GoogleLogin(ctx context.Context, email, deviceID string, rememberMe bool, userAgent, ip *string) (string, string, error) {
	start := time.Now()
	access, refresh, err := s.delegate.GoogleLogin(ctx, email, deviceID, rememberMe, userAgent, ip)
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.AuthOps.WithLabelValues("google_login", result).Inc()
	metrics.OryOps.WithLabelValues("kratos_get_by_email").Observe(time.Since(start).Seconds())
	return access, refresh, err
}

var _ AuthServiceI = (*InstrumentedAuthService)(nil)
