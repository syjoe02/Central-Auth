// Package kafka provides an asynchronous Kafka producer for access-log events.
//
// Design goals:
//   - Zero latency impact on HTTP handlers: Publish is always non-blocking.
//   - Clean shutdown: Close drains the internal channel before closing the writer.
//   - Degraded mode: when the broker is unreachable in non-production, a
//     NoopPublisher is returned so the service continues without Kafka.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	kafkago "github.com/segmentio/kafka-go"

	"central-auth/internal/config"
	"central-auth/internal/metrics"
)

// AccessLogEvent is the payload written to the access-logs Kafka topic for
// every HTTP/gRPC request (path, status, latency).
type AccessLogEvent struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	LatencyMs  int64  `json:"latency_ms"`
	UserID     string `json:"user_id"`
	Timestamp  string `json:"timestamp"` // RFC3339Nano, UTC
}

// AuthSessionEvent is published once per successful login (both /auth/* and
// /bff/login paths). It carries the full auth context assembled from:
//   - the HTTP request (IPAddress, UserAgent, DeviceID)
//   - the Hydra access token claims (HydraJTI = jwt.RegisteredClaims.ID)
//   - the Kratos identity (KratosID)
//
// The EventType field discriminates AuthSessionEvent from AccessLogEvent when
// both coexist on the same "access-logs" topic. Consumers filter on this field.
type AuthSessionEvent struct {
	EventType string `json:"event_type"` // always "auth.session.created"
	KratosID  string `json:"kratos_id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	HydraJTI  string `json:"hydra_jti"`
	DeviceID  string `json:"device_id"`
	Timestamp string `json:"timestamp"` // RFC3339Nano, UTC
}

// EventPublisher is the interface consumed by middleware and service layer.
// Both *Producer and *NoopPublisher satisfy it.
type EventPublisher interface {
	Publish(event AccessLogEvent)
	PublishAuthSession(event AuthSessionEvent)
	Close(ctx context.Context) error
}

// Producer owns two background worker goroutines: one for AccessLogEvents
// (high-frequency HTTP/gRPC path) and one for AuthSessionEvents (low-frequency
// login path). Separating the channels prevents high-volume access logs from
// causing head-of-line blocking on auth session events.
//
// Both workers drain their channels and exit cleanly when Close is called.
type Producer struct {
	writer      *kafkago.Writer
	ch          chan AccessLogEvent
	done        chan struct{}
	authCh      chan AuthSessionEvent
	authDone    chan struct{}
	closeOnce   sync.Once    // H-2: guards close(p.ch) against double-Close panics
	dropped     atomic.Int64 // observable via central_auth_kafka_events_dropped_total
	authDropped atomic.Int64
	logger      *slog.Logger
}

// NewProducer constructs a Producer and probes the first broker with a 5-second
// deadline. On success it returns a ready *Producer.
// On connection failure:
//   - cfg.IsProduction == true  → panics (process exits, no Kafka = no start)
//   - cfg.IsProduction == false → logs warn, returns *NoopPublisher + error
func NewProducer(cfg config.KafkaConfig) (EventPublisher, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()

	conn, err := kafkago.DialContext(probeCtx, "tcp", cfg.Brokers[0])
	if err != nil {
		if cfg.IsProduction {
			logger.Error("Kafka broker unreachable in production — exiting",
				slog.String("broker", cfg.Brokers[0]),
				slog.Any("error", err),
			)
			os.Exit(1)
		}
		logger.Warn("Kafka broker unreachable (degraded mode — access logs disabled)",
			slog.String("broker", cfg.Brokers[0]),
			slog.Any("error", err),
		)
		return &NoopPublisher{}, err
	}
	conn.Close()
	logger.Info("Kafka connected",
		slog.String("broker", cfg.Brokers[0]),
		slog.String("topic", cfg.Topic),
	)

	w := &kafkago.Writer{
		Addr:         kafkago.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafkago.LeastBytes{},
		WriteTimeout: cfg.WriteTimeout,
		RequiredAcks: kafkago.RequireAll, // P0: acks=all for at-least-once durability
		Async:        false,              // the worker goroutine provides async dispatch
		ErrorLogger: kafkago.LoggerFunc(func(msg string, args ...interface{}) {
			logger.Error("kafka writer error",
				slog.String("detail", fmt.Sprintf(msg, args...)),
			)
		}),
	}

	p := &Producer{
		writer:   w,
		ch:       make(chan AccessLogEvent, cfg.ChannelSize),
		done:     make(chan struct{}),
		authCh:   make(chan AuthSessionEvent, 512), // auth logins are low-frequency
		authDone: make(chan struct{}),
		logger:   logger,
	}
	go p.runWorker()
	go p.runAuthWorker()
	return p, nil
}

// PublishAuthSession enqueues an AuthSessionEvent for asynchronous delivery.
// It is always non-blocking: if the channel is full the event is dropped.
// Callers must not call PublishAuthSession after Close.
func (p *Producer) PublishAuthSession(event AuthSessionEvent) {
	select {
	case p.authCh <- event:
	default:
		p.authDropped.Add(1)
		// Use the dedicated auth-sessions dropped counter, not KafkaEventsDropped
		// (access logs). Dropped auth-session events are lost audit records and
		// need a distinct alert threshold from high-frequency HTTP log drops.
		metrics.KafkaAuthSessionsDropped.Inc()
	}
}

// Publish enqueues an event for asynchronous delivery. It is always non-blocking:
// if the channel is full the event is dropped and the dropped counter increments.
// Callers must not call Publish after Close has been called (see main.go shutdown
// ordering: HTTP servers drain fully before kafkaProducer.Close is invoked).
func (p *Producer) Publish(event AccessLogEvent) {
	select {
	case p.ch <- event:
	default:
		p.dropped.Add(1)
		metrics.KafkaEventsDropped.Inc()
	}
}

// Close signals both workers to drain and exit, then closes the Kafka writer.
// It is safe to call Close multiple times (idempotent via sync.Once).
// Pass a context with an appropriate deadline to bound the drain time.
//
// Both workers are waited on under the same context deadline. If the deadline
// fires, writer.Close is called immediately and the remaining buffered event
// counts are logged so operators know what was lost.
func (p *Producer) Close(ctx context.Context) error {
	// M-1: capture counts before closing so the timeout log is not racing the drain.
	remaining := len(p.ch)
	authRemaining := len(p.authCh)
	// H-2: sync.Once ensures both channels are closed exactly once.
	p.closeOnce.Do(func() {
		close(p.ch)
		close(p.authCh)
	})
	// Wait for both workers using a single helper so the same ctx deadline covers
	// both. A sequential loop would let the first worker consume the full deadline,
	// leaving zero budget for the second — potentially racing writer.Close.
	waitDone := func(ch chan struct{}) bool {
		select {
		case <-ch:
			return true
		case <-ctx.Done():
			return false
		}
	}
	// Evaluate both independently — short-circuit (||) would skip the second
	// wait if the first times out, leaving runAuthWorker racing writer.Close.
	d1 := waitDone(p.done)
	d2 := waitDone(p.authDone)
	if !d1 || !d2 {
		p.logger.Warn("Kafka producer close timed out; events may be lost",
			slog.Int("remaining", remaining),
			slog.Int("authRemaining", authRemaining),
		)
	}
	return p.writer.Close()
}

// runWorker is the single background goroutine owned by Producer.
// It reads events from p.ch until the channel is closed, then signals p.done.
func (p *Producer) runWorker() {
	defer close(p.done)
	for event := range p.ch {
		payload, err := json.Marshal(event)
		if err != nil {
			p.logger.Error("marshal error (dropping access-log event)",
				slog.String("path", event.Path),
				slog.Any("error", err),
			)
			continue
		}
		// H-1: writeMessage uses defer cancel() in its own scope so the context
		// timer is always released even if WriteMessages panics.
		if err := p.writeMessage(payload); err != nil {
			p.logger.Error("write error (dropping access-log event)",
				slog.String("path", event.Path),
				slog.Any("error", err),
			)
		}
	}
}

// runAuthWorker is the background goroutine for AuthSessionEvent delivery.
// Mirrors runWorker but drains authCh and signals authDone on exit.
func (p *Producer) runAuthWorker() {
	defer close(p.authDone)
	for event := range p.authCh {
		payload, err := json.Marshal(event)
		if err != nil {
			p.logger.Error("marshal error (dropping auth-session event)",
				slog.String("kratosID", event.KratosID),
				slog.Any("error", err),
			)
			continue
		}
		if err := p.writeMessage(payload); err != nil {
			p.logger.Error("write error (dropping auth-session event)",
				slog.String("kratosID", event.KratosID),
				slog.Any("error", err),
			)
		} else {
			metrics.KafkaAuthSessionsPublished.Inc()
		}
	}
}

// writeMessage performs a single timed Kafka write. Extracted from runWorker
// so that defer cancel() fires at function return, not at runWorker return —
// preventing timer goroutine accumulation across loop iterations (H-1 fix).
func (p *Producer) writeMessage(payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // H-1: always runs, even on panic from WriteMessages
	return p.writer.WriteMessages(ctx, kafkago.Message{Value: payload})
}

// ── NoopPublisher ─────────────────────────────────────────────────────────────

// NoopPublisher satisfies EventPublisher with no-op implementations.
// Returned when the Kafka broker is unreachable in non-production mode, letting
// the service start in degraded state without access logging.
type NoopPublisher struct{}

func (n *NoopPublisher) Publish(_ AccessLogEvent)             {}
func (n *NoopPublisher) PublishAuthSession(_ AuthSessionEvent) {}
func (n *NoopPublisher) Close(_ context.Context) error        { return nil }
