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
	"log"
	"sync"
	"sync/atomic"
	"time"

	kafkago "github.com/segmentio/kafka-go"

	"central-auth/internal/config"
	"central-auth/internal/metrics"
)

// AccessLogEvent is the payload written to the access-logs Kafka topic.
type AccessLogEvent struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	LatencyMs  int64  `json:"latency_ms"`
	UserID     string `json:"user_id"`
	Timestamp  string `json:"timestamp"` // RFC3339Nano, UTC
}

// EventPublisher is the interface consumed by the Kafka access-log middleware.
// Both *Producer and *NoopPublisher satisfy it.
type EventPublisher interface {
	Publish(event AccessLogEvent)
	Close(ctx context.Context) error
}

// Producer owns a single background worker goroutine that drains an internal
// channel and writes events to Kafka. The worker exits cleanly when Close is
// called: Close closes the channel, causing the for-range loop to drain and
// terminate naturally.
type Producer struct {
	writer    *kafkago.Writer
	ch        chan AccessLogEvent
	done      chan struct{}
	closeOnce sync.Once    // H-2: guards close(p.ch) against double-Close panics
	dropped   atomic.Int64 // observable via central_auth_kafka_events_dropped_total
}

// NewProducer constructs a Producer and probes the first broker with a 5-second
// deadline. On success it returns a ready *Producer.
// On connection failure:
//   - cfg.IsProduction == true  → log.Fatalf (process exits, no Kafka = no start)
//   - cfg.IsProduction == false → logs [WARN], returns *NoopPublisher + error
func NewProducer(cfg config.KafkaConfig) (EventPublisher, error) {
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()

	conn, err := kafkago.DialContext(probeCtx, "tcp", cfg.Brokers[0])
	if err != nil {
		if cfg.IsProduction {
			log.Fatalf("[FATAL] Kafka broker %q unreachable in production: %v", cfg.Brokers[0], err)
		}
		log.Printf("[WARN] Kafka broker %q unreachable (degraded mode — access logs disabled): %v", cfg.Brokers[0], err)
		return &NoopPublisher{}, err
	}
	conn.Close()
	log.Printf("[INFO] Kafka connected to %q (topic: %s)", cfg.Brokers[0], cfg.Topic)

	w := &kafkago.Writer{
		Addr:         kafkago.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafkago.LeastBytes{},
		WriteTimeout: cfg.WriteTimeout,
		RequiredAcks: kafkago.RequireOne,
		Async:        false, // the worker goroutine provides async dispatch
		ErrorLogger: kafkago.LoggerFunc(func(msg string, args ...interface{}) {
			log.Printf("[KAFKA ERROR] "+msg, args...)
		}),
	}

	p := &Producer{
		writer: w,
		ch:     make(chan AccessLogEvent, cfg.ChannelSize),
		done:   make(chan struct{}),
	}
	go p.runWorker()
	return p, nil
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

// Close signals the worker to drain and exit, then closes the Kafka writer.
// It is safe to call Close multiple times (idempotent via sync.Once).
// Pass a context with an appropriate deadline to bound the drain time.
func (p *Producer) Close(ctx context.Context) error {
	// M-1: capture count before closing so the timeout log is not racing the drain.
	remaining := len(p.ch)
	// H-2: sync.Once ensures close(p.ch) is called exactly once.
	p.closeOnce.Do(func() { close(p.ch) })
	select {
	case <-p.done:
	case <-ctx.Done():
		log.Printf("[WARN] Kafka producer close timed out; ~%d events may be lost", remaining)
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
			log.Printf("[KAFKA] marshal error (dropping event): %v", err)
			continue
		}
		// H-1: writeMessage uses defer cancel() in its own scope so the context
		// timer is always released even if WriteMessages panics.
		if err := p.writeMessage(payload); err != nil {
			log.Printf("[KAFKA] write error (dropping event for path=%s): %v", event.Path, err)
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

func (n *NoopPublisher) Publish(_ AccessLogEvent)      {}
func (n *NoopPublisher) Close(_ context.Context) error { return nil }
