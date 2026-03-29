package repository

import (
	"context"
	"time"

	"central-auth/internal/domain"
	"central-auth/internal/metrics"
)

// InstrumentedDeviceSessionRepository wraps DeviceSessionRepository and records
// Postgres latency metrics for each operation.
type InstrumentedDeviceSessionRepository struct {
	delegate DeviceSessionRepository
}

// NewInstrumentedDeviceSessionRepository creates an instrumented wrapper.
func NewInstrumentedDeviceSessionRepository(delegate DeviceSessionRepository) *InstrumentedDeviceSessionRepository {
	return &InstrumentedDeviceSessionRepository{delegate: delegate}
}

func (r *InstrumentedDeviceSessionRepository) SaveDeviceSession(ctx context.Context, session *domain.DeviceSession) error {
	start := time.Now()
	err := r.delegate.SaveDeviceSession(ctx, session)
	metrics.PostgresOps.WithLabelValues("save_device_session").Observe(time.Since(start).Seconds())
	return err
}

func (r *InstrumentedDeviceSessionRepository) UpdateLastUsedAt(ctx context.Context, kratosID, deviceID string) error {
	start := time.Now()
	err := r.delegate.UpdateLastUsedAt(ctx, kratosID, deviceID)
	metrics.PostgresOps.WithLabelValues("update_last_used_at").Observe(time.Since(start).Seconds())
	return err
}

func (r *InstrumentedDeviceSessionRepository) RevokeDevice(ctx context.Context, kratosID, deviceID string) error {
	start := time.Now()
	err := r.delegate.RevokeDevice(ctx, kratosID, deviceID)
	metrics.PostgresOps.WithLabelValues("revoke_device").Observe(time.Since(start).Seconds())
	return err
}

func (r *InstrumentedDeviceSessionRepository) RevokeAllDevices(ctx context.Context, kratosID string) error {
	start := time.Now()
	err := r.delegate.RevokeAllDevices(ctx, kratosID)
	metrics.PostgresOps.WithLabelValues("revoke_all_devices").Observe(time.Since(start).Seconds())
	return err
}

func (r *InstrumentedDeviceSessionRepository) GetDeviceSessions(ctx context.Context, kratosID string) ([]domain.DeviceSession, error) {
	start := time.Now()
	sessions, err := r.delegate.GetDeviceSessions(ctx, kratosID)
	metrics.PostgresOps.WithLabelValues("get_device_sessions").Observe(time.Since(start).Seconds())
	return sessions, err
}

func (r *InstrumentedDeviceSessionRepository) CountActiveDevices(ctx context.Context, kratosID string) (int, error) {
	start := time.Now()
	count, err := r.delegate.CountActiveDevices(ctx, kratosID)
	metrics.PostgresOps.WithLabelValues("count_active_devices").Observe(time.Since(start).Seconds())
	return count, err
}

var _ DeviceSessionRepository = (*InstrumentedDeviceSessionRepository)(nil)
