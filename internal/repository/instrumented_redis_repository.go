package repository

import (
	"context"
	"time"

	"central-auth/internal/metrics"
)

// InstrumentedRedisRepo wraps RedisRepo and records Prometheus latency metrics.
type InstrumentedRedisRepo struct {
	delegate RedisRepo
}

// NewInstrumentedRedisRepo creates an instrumented wrapper.
func NewInstrumentedRedisRepo(delegate RedisRepo) *InstrumentedRedisRepo {
	return &InstrumentedRedisRepo{delegate: delegate}
}

func (r *InstrumentedRedisRepo) SaveLogin(ctx context.Context, kratosID, deviceID, hydraRefreshToken string, ttl time.Duration) error {
	start := time.Now()
	err := r.delegate.SaveLogin(ctx, kratosID, deviceID, hydraRefreshToken, ttl)
	metrics.RedisOps.WithLabelValues("save_login").Observe(time.Since(start).Seconds())
	return err
}

func (r *InstrumentedRedisRepo) GetDeviceRefreshToken(ctx context.Context, kratosID, deviceID string) (string, error) {
	start := time.Now()
	token, err := r.delegate.GetDeviceRefreshToken(ctx, kratosID, deviceID)
	metrics.RedisOps.WithLabelValues("get_device_refresh_token").Observe(time.Since(start).Seconds())
	return token, err
}

func (r *InstrumentedRedisRepo) RotateRefreshToken(ctx context.Context, kratosID, deviceID, newToken string, ttl time.Duration) error {
	start := time.Now()
	err := r.delegate.RotateRefreshToken(ctx, kratosID, deviceID, newToken, ttl)
	metrics.RedisOps.WithLabelValues("rotate_refresh_token").Observe(time.Since(start).Seconds())
	return err
}

func (r *InstrumentedRedisRepo) LogoutDevice(ctx context.Context, kratosID, deviceID string) error {
	start := time.Now()
	err := r.delegate.LogoutDevice(ctx, kratosID, deviceID)
	metrics.RedisOps.WithLabelValues("logout_device").Observe(time.Since(start).Seconds())
	return err
}

func (r *InstrumentedRedisRepo) LogoutAll(ctx context.Context, kratosID string) error {
	start := time.Now()
	err := r.delegate.LogoutAll(ctx, kratosID)
	metrics.RedisOps.WithLabelValues("logout_all").Observe(time.Since(start).Seconds())
	return err
}

var _ RedisRepo = (*InstrumentedRedisRepo)(nil)
