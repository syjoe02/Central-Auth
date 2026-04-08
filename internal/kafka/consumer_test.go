package kafka

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"central-auth/internal/domain"
	"central-auth/internal/metrics"
	"central-auth/internal/repository"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// compile-time interface check — catches missed methods when DeviceSessionRepository grows
var _ repository.DeviceSessionRepository = (*mockDeviceSessionRepo)(nil)

// ── mock DeviceSessionRepository ─────────────────────────────────────────────

type mockDeviceSessionRepo struct {
	saved []*domain.DeviceSession
	err   error
}

func (m *mockDeviceSessionRepo) SaveDeviceSession(_ context.Context, s *domain.DeviceSession) error {
	if m.err != nil {
		return m.err
	}
	m.saved = append(m.saved, s)
	return nil
}
func (m *mockDeviceSessionRepo) UpdateLastUsedAt(_ context.Context, _, _ string) error { return nil }
func (m *mockDeviceSessionRepo) RevokeDevice(_ context.Context, _, _ string) error     { return nil }
func (m *mockDeviceSessionRepo) RevokeAllDevices(_ context.Context, _ string) error    { return nil }
func (m *mockDeviceSessionRepo) GetDeviceSessions(_ context.Context, _ string) ([]domain.DeviceSession, error) {
	return nil, nil
}
func (m *mockDeviceSessionRepo) CountActiveDevices(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func marshalAccessLogEvent(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(AccessLogEvent{
		Path:       "/bff/login",
		StatusCode: 200,
		LatencyMs:  42,
		UserID:     "user-123",
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("marshal AccessLogEvent: %v", err)
	}
	return b
}

func marshalAuthSessionEvent(t *testing.T, e AuthSessionEvent) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal AuthSessionEvent: %v", err)
	}
	return b
}

func newConsumer(repo *mockDeviceSessionRepo) *DeviceSessionConsumer {
	return &DeviceSessionConsumer{
		repo:    repo,
		logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
		runDone: make(chan struct{}),
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestConsumer_SkipsNonAuthSessionEvents(t *testing.T) {
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)

	c.process(marshalAccessLogEvent(t))

	if len(repo.saved) != 0 {
		t.Errorf("expected no SaveDeviceSession calls, got %d", len(repo.saved))
	}
}

func TestConsumer_ProcessesAuthSessionCreated(t *testing.T) {
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)

	ts := time.Now().UTC().Truncate(time.Second)
	event := AuthSessionEvent{
		EventType: "auth.session.created",
		KratosID:  "kratos-abc",
		DeviceID:  "device-xyz",
		HydraJTI:  "jti-001",
		IPAddress: "192.168.1.1",
		UserAgent: "TestAgent/1.0",
		Timestamp: ts.Format(time.RFC3339Nano),
	}

	c.process(marshalAuthSessionEvent(t, event))

	if len(repo.saved) != 1 {
		t.Fatalf("expected 1 SaveDeviceSession call, got %d", len(repo.saved))
	}
	got := repo.saved[0]
	if got.KratosID != "kratos-abc" {
		t.Errorf("KratosID: want kratos-abc, got %s", got.KratosID)
	}
	if got.DeviceID != "device-xyz" {
		t.Errorf("DeviceID: want device-xyz, got %s", got.DeviceID)
	}
	if got.HydraJTI == nil || *got.HydraJTI != "jti-001" {
		t.Errorf("HydraJTI: want jti-001, got %v", got.HydraJTI)
	}
	if got.IP == nil || *got.IP != "192.168.1.1" {
		t.Errorf("IP: want 192.168.1.1, got %v", got.IP)
	}
	if got.UserAgent == nil || *got.UserAgent != "TestAgent/1.0" {
		t.Errorf("UserAgent: want TestAgent/1.0, got %v", got.UserAgent)
	}
	if got.Revoked {
		t.Error("Revoked: want false, got true")
	}
	if got.LastUsedAt == nil {
		t.Error("LastUsedAt: want non-nil (seeded to IssuedAt), got nil")
	} else if !got.LastUsedAt.Equal(ts) {
		t.Errorf("LastUsedAt: want %v, got %v", ts, *got.LastUsedAt)
	}
}

func TestConsumer_NilPointerFieldsWhenEmpty(t *testing.T) {
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)

	event := AuthSessionEvent{
		EventType: "auth.session.created",
		KratosID:  "k1",
		DeviceID:  "d1",
		HydraJTI:  "",
		IPAddress: "",
		UserAgent: "",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	c.process(marshalAuthSessionEvent(t, event))

	if len(repo.saved) != 1 {
		t.Fatalf("expected 1 call, got %d", len(repo.saved))
	}
	got := repo.saved[0]
	if got.HydraJTI != nil {
		t.Errorf("HydraJTI: want nil, got %q", *got.HydraJTI)
	}
	if got.IP != nil {
		t.Errorf("IP: want nil, got %q", *got.IP)
	}
	if got.UserAgent != nil {
		t.Errorf("UserAgent: want nil, got %q", *got.UserAgent)
	}
}

func TestConsumer_DBErrorLogsAndContinues(t *testing.T) {
	repo := &mockDeviceSessionRepo{err: errors.New("postgres unavailable")}
	c := newConsumer(repo)

	event := AuthSessionEvent{
		EventType: "auth.session.created",
		KratosID:  "k1",
		DeviceID:  "d1",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	// Must not panic and must not call SaveDeviceSession successfully.
	c.process(marshalAuthSessionEvent(t, event))
	if len(repo.saved) != 0 {
		t.Errorf("expected no successful saves on DB error, got %d", len(repo.saved))
	}
}

func TestConsumer_BadJSONLogsAndContinues(t *testing.T) {
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)

	// Must not panic and must not call SaveDeviceSession.
	c.process([]byte(`{not valid json`))

	if len(repo.saved) != 0 {
		t.Errorf("expected no SaveDeviceSession calls on bad JSON, got %d", len(repo.saved))
	}
}

func TestConsumer_TimestampParsed(t *testing.T) {
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)

	want := time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC)
	event := AuthSessionEvent{
		EventType: "auth.session.created",
		KratosID:  "k1",
		DeviceID:  "d1",
		Timestamp: want.Format(time.RFC3339Nano),
	}

	c.process(marshalAuthSessionEvent(t, event))

	if len(repo.saved) != 1 {
		t.Fatalf("expected 1 call, got %d", len(repo.saved))
	}
	if !repo.saved[0].IssuedAt.Equal(want) {
		t.Errorf("IssuedAt: want %v, got %v", want, repo.saved[0].IssuedAt)
	}
}

func TestConsumer_TimestampMustBeRFC3339Nano_FallsBackToNow(t *testing.T) {
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)

	event := AuthSessionEvent{
		EventType: "auth.session.created",
		KratosID:  "k1",
		DeviceID:  "d1",
		Timestamp: "not-a-timestamp",
	}
	before := time.Now()
	c.process(marshalAuthSessionEvent(t, event))
	after := time.Now()

	if len(repo.saved) != 1 {
		t.Fatalf("expected 1 call on bad timestamp (falls back to now), got %d", len(repo.saved))
	}
	// IssuedAt must have been set to approximately now.
	got := repo.saved[0].IssuedAt
	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Errorf("IssuedAt %v is not close to now (before=%v after=%v)", got, before, after)
	}
}

func TestConsumer_UnknownEventTypeSkipped(t *testing.T) {
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)

	payload, _ := json.Marshal(map[string]string{
		"event_type": "auth.session.deleted",
		"kratos_id":  "k1",
	})
	c.process(payload)

	if len(repo.saved) != 0 {
		t.Errorf("expected no SaveDeviceSession calls for unknown event_type, got %d", len(repo.saved))
	}
}

// ── Phase 3: lag metric tests ─────────────────────────────────────────────────

func TestUpdateLagMetric_SetsGauge(t *testing.T) {
	metrics.KafkaConsumerLag.Set(0)
	updateLagMetric(42)
	got := testutil.ToFloat64(metrics.KafkaConsumerLag)
	if got != 42 {
		t.Errorf("KafkaConsumerLag: want 42, got %v", got)
	}
}

func TestUpdateLagMetric_SetsZero(t *testing.T) {
	metrics.KafkaConsumerLag.Set(99)
	updateLagMetric(0)
	got := testutil.ToFloat64(metrics.KafkaConsumerLag)
	if got != 0 {
		t.Errorf("KafkaConsumerLag: want 0, got %v", got)
	}
}

func TestConsumer_RunDone_ClosesAfterContextCancel(t *testing.T) {
	// Verifies the runDone channel is closed when Run exits.
	// The consumer has a nil reader; Run returns immediately because the nil
	// guard at the top of Run causes an early return when reader is nil.
	repo := &mockDeviceSessionRepo{}
	c := newConsumer(repo)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run starts

	go c.Run(ctx)
	select {
	case <-c.RunDone():
		// pass
	case <-time.After(2 * time.Second):
		t.Fatal("RunDone not closed within 2s after context cancel")
	}
}

// ── Phase 4: PII log tests ────────────────────────────────────────────────────

// piiEvent is a fully-populated AuthSessionEvent used across PII sub-tests.
// It deliberately includes an IP address and a user-agent that must NEVER
// appear in any log output emitted by process().
var piiEvent = AuthSessionEvent{
	EventType: "auth.session.created",
	KratosID:  "k1",
	DeviceID:  "d1",
	HydraJTI:  "jti-1",
	IPAddress: "203.0.113.1",
	UserAgent: "Mozilla/5.0",
}

// assertNoPII fails the test if the log output contains PII fields.
func assertNoPII(t *testing.T, output string) {
	t.Helper()
	if strings.Contains(output, "203.0.113.1") {
		t.Error("log output contains IP address (PII leak)")
	}
	if strings.Contains(output, "Mozilla/5.0") {
		t.Error("log output contains user agent (PII leak)")
	}
}

// TestConsumer_ProcessLogs_NoPII verifies that none of the log call sites
// inside process() emit PII (ip_address, user_agent) across all code paths:
// success, DB error, and bad-timestamp fallback.
func TestConsumer_ProcessLogs_NoPII(t *testing.T) {
	t.Run("success_path", func(t *testing.T) {
		var buf bytes.Buffer
		event := piiEvent
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		repo := &mockDeviceSessionRepo{}
		c := &DeviceSessionConsumer{repo: repo, logger: slog.New(slog.NewJSONHandler(&buf, nil)), runDone: make(chan struct{})}
		c.process(marshalAuthSessionEvent(t, event))
		assertNoPII(t, buf.String())
	})

	t.Run("db_error_path", func(t *testing.T) {
		// Exercises c.logger.Error("SaveDeviceSession error ...") — the log site
		// most likely to have a future field added alongside kratosID/deviceID.
		var buf bytes.Buffer
		event := piiEvent
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		repo := &mockDeviceSessionRepo{err: errors.New("db down")}
		c := &DeviceSessionConsumer{repo: repo, logger: slog.New(slog.NewJSONHandler(&buf, nil)), runDone: make(chan struct{})}
		c.process(marshalAuthSessionEvent(t, event))
		assertNoPII(t, buf.String())
	})

	t.Run("bad_timestamp_path", func(t *testing.T) {
		// Exercises c.logger.Warn("parse timestamp error ...") which logs kratosID.
		var buf bytes.Buffer
		event := piiEvent
		event.Timestamp = "not-a-timestamp"
		repo := &mockDeviceSessionRepo{}
		c := &DeviceSessionConsumer{repo: repo, logger: slog.New(slog.NewJSONHandler(&buf, nil)), runDone: make(chan struct{})}
		c.process(marshalAuthSessionEvent(t, event))
		assertNoPII(t, buf.String())
	})
}
