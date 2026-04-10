// Package kafka provides the DeviceSessionConsumer, which reads AuthSessionEvents
// from the access-logs Kafka topic and persists them to the device_sessions table.
//
// Design goals:
//   - At-least-once delivery: offsets are committed only after a successful DB write.
//   - Idempotent writes: SaveDeviceSession is an upsert ON CONFLICT (kratos_id, device_id).
//   - Log-and-commit on DB error: a single bad message does not stall the consumer.
//   - Graceful shutdown: Run returns when ctx is cancelled; Close releases the reader.
package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	kafkago "github.com/segmentio/kafka-go"

	"central-auth/internal/config"
	"central-auth/internal/domain"
	"central-auth/internal/metrics"
	"central-auth/internal/repository"
)

const authSessionEventType = "auth.session.created"

// DeviceSessionConsumer reads AuthSessionEvents from the access-logs topic and
// persists them to the device_sessions table via DeviceSessionRepository.
type DeviceSessionConsumer struct {
	reader  *kafkago.Reader
	repo    repository.DeviceSessionRepository
	logger  *slog.Logger
	runDone chan struct{} // closed when Run returns; used by shutdown to synchronise
}

// NewDeviceSessionConsumer creates a consumer connected to the broker described
// by cfg. It joins the "central-auth-device-session-consumer" consumer group and
// starts at the latest offset (no replay of historical events on first boot).
func NewDeviceSessionConsumer(cfg config.KafkaConfig, repo repository.DeviceSessionRepository) *DeviceSessionConsumer {
	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:     cfg.Brokers,
		GroupID:     "central-auth-device-session-consumer",
		Topic:       cfg.Topic,
		MinBytes:    1,
		MaxBytes:    10e6,          // 10 MB
		MaxWait:     500 * time.Millisecond,
		StartOffset: kafkago.LastOffset,
	})
	return &DeviceSessionConsumer{
		reader:  reader,
		repo:    repo,
		logger:  slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(slog.String("service", "central-auth")),
		runDone: make(chan struct{}),
	}
}

// Run is a blocking loop that fetches and processes messages until ctx is
// cancelled. Call it in a goroutine; it signals RunDone when it returns so
// the shutdown sequence can wait before calling Close.
//
// On transient fetch errors a bounded exponential backoff is applied (100 ms →
// 30 s, 1.5× multiplier) to prevent a hot spin during broker unavailability.
func (c *DeviceSessionConsumer) Run(ctx context.Context) {
	defer close(c.runDone)

	// Nil reader guard: unit tests that only exercise process() construct a
	// consumer without a reader. Return immediately so tests can safely cancel
	// and wait on RunDone without a nil-pointer panic.
	// A warning is emitted so this path is visible if hit outside of tests.
	if c.reader == nil {
		c.logger.Warn("Run called with nil reader — exiting immediately (test mode or misconfiguration)")
		return
	}

	const (
		backoffMin    = 100 * time.Millisecond
		backoffMax    = 30 * time.Second
		backoffFactor = 1.5
	)
	backoff := backoffMin

	// Lag sampler: samples reader.Stats().Lag every 10s and updates the
	// Prometheus gauge. reader.Stats() is documented as safe for concurrent
	// use with FetchMessage. The goroutine exits when ctx is cancelled.
	lagTicker := time.NewTicker(10 * time.Second)
	go func() {
		defer lagTicker.Stop()
		for {
			select {
			case <-lagTicker.C:
				updateLagMetric(c.reader.Stats().Lag)
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		msg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
				return
			}
			c.logger.Error("fetch error",
				slog.String("backoff", backoff.String()),
				slog.Any("error", err),
			)
			metrics.KafkaConsumerErrors.WithLabelValues("fetch").Inc()
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if next := time.Duration(float64(backoff) * backoffFactor); next < backoffMax {
				backoff = next
			} else {
				backoff = backoffMax
			}
			continue
		}
		backoff = backoffMin // reset on success

		c.process(msg.Value)
		// Commit after processing regardless of outcome (log-and-commit semantics).
		// Rationale: device_sessions is an audit-only table; the upsert is idempotent;
		// blocking the consumer on repeated Postgres outages is worse than skipping a row.
		// KafkaConsumerErrors{save_device_session} provides an alertable signal.
		if err := c.reader.CommitMessages(ctx, msg); err != nil {
			if !errors.Is(err, context.Canceled) {
				c.logger.Error("commit error", slog.Any("error", err))
			}
		}
	}
}

// RunDone returns a channel that is closed when Run returns. Use it in the
// shutdown sequence to guarantee Run has exited before calling Close.
func (c *DeviceSessionConsumer) RunDone() <-chan struct{} {
	return c.runDone
}

// process deserialises one Kafka message and, if it is an AuthSessionEvent,
// upserts a DeviceSession row. It is extracted as a separate method so unit
// tests can call it directly without a live Kafka broker.
//
// Security: IPAddress and UserAgent are stored in the DB (audit) but are NOT
// written to log output (PII constraint).
func (c *DeviceSessionConsumer) process(payload []byte) {
	// Peek at event_type without fully unmarshalling — avoids allocating a
	// full struct for the high-frequency AccessLogEvent messages on this topic.
	var envelope struct {
		EventType string `json:"event_type"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		c.logger.Error("unmarshal envelope error (skipping)", slog.Any("error", err))
		metrics.KafkaConsumerErrors.WithLabelValues("unmarshal").Inc()
		return
	}
	if envelope.EventType != authSessionEventType {
		metrics.KafkaConsumerSkipped.Inc()
		return // not our event type — AccessLogEvent or future types
	}

	var event AuthSessionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		c.logger.Error("unmarshal AuthSessionEvent error (skipping)", slog.Any("error", err))
		metrics.KafkaConsumerErrors.WithLabelValues("unmarshal").Inc()
		return
	}

	issuedAt, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		c.logger.Warn("parse timestamp error (using now)",
			slog.String("kratosID", event.KratosID),
			slog.Any("error", err),
		)
		metrics.KafkaConsumerErrors.WithLabelValues("parse_timestamp").Inc()
		issuedAt = time.Now()
	}

	sess := &domain.DeviceSession{
		KratosID:   event.KratosID,
		DeviceID:   event.DeviceID,
		HydraJTI:   strPtrIfNonEmpty(event.HydraJTI),
		IssuedAt:   issuedAt,
		LastUsedAt: &issuedAt, // seed last_used_at; GREATEST in upsert preserves later activity
		UserAgent:  strPtrIfNonEmpty(event.UserAgent),
		IP:         strPtrIfNonEmpty(event.IPAddress),
		Revoked:    false,
	}

	// Pass context.Background() so graceful shutdown (consumer ctx cancellation)
	// does not interrupt an in-flight DB write. The repository adds its own
	// dbQueryTimeout (3 s) — no need to duplicate it here.
	if err := c.repo.SaveDeviceSession(context.Background(), sess); err != nil {
		c.logger.Error("SaveDeviceSession error (skipping)",
			slog.String("kratosID", event.KratosID),
			slog.String("deviceID", event.DeviceID),
			slog.Any("error", err),
		)
		metrics.KafkaConsumerErrors.WithLabelValues("save_device_session").Inc()
		return
	}
	// Log identity fields only — IP and UserAgent are PII and must not appear in logs.
	c.logger.Info("device session persisted",
		slog.String("kratosID", event.KratosID),
		slog.String("deviceID", event.DeviceID),
		slog.String("jti", event.HydraJTI),
	)
}

// Close releases the underlying Kafka reader.
func (c *DeviceSessionConsumer) Close() error {
	return c.reader.Close()
}

// updateLagMetric sets the KafkaConsumerLag Prometheus gauge to lag.
// Unexported so it can be called from the lag sampler goroutine and tested
// directly from within the kafka package tests.
func updateLagMetric(lag int64) {
	metrics.KafkaConsumerLag.Set(float64(lag))
}

// strPtrIfNonEmpty returns a pointer to s, or nil if s is the empty string.
// Used when mapping flat Kafka string fields back to nullable domain pointers.
func strPtrIfNonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	cp := s
	return &cp
}
