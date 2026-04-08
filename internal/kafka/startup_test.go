package kafka_test

import (
	"context"
	"testing"

	"central-auth/internal/kafka"
)

func TestShouldStartConsumer_FalseForNoopPublisher(t *testing.T) {
	pub := &kafka.NoopPublisher{}
	if kafka.ShouldStartConsumer(pub) {
		t.Error("ShouldStartConsumer: want false for NoopPublisher, got true")
	}
}

func TestShouldStartConsumer_TrueForRealPublisher(t *testing.T) {
	// Confirm a non-NoopPublisher returns true.
	var pub kafka.EventPublisher = &stubPublisher{}
	if !kafka.ShouldStartConsumer(pub) {
		t.Error("ShouldStartConsumer: want true for non-NoopPublisher, got false")
	}
}

// stubPublisher is a minimal EventPublisher that is not a *NoopPublisher.
type stubPublisher struct{}

func (s *stubPublisher) Publish(_ kafka.AccessLogEvent)             {}
func (s *stubPublisher) PublishAuthSession(_ kafka.AuthSessionEvent) {}
func (s *stubPublisher) Close(_ context.Context) error               { return nil }
