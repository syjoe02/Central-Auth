package kafka

// ShouldStartConsumer returns true when pub is a real Kafka producer
// (i.e., not a NoopPublisher). Use this in main.go to avoid starting
// the DeviceSessionConsumer when the broker is unreachable.
func ShouldStartConsumer(pub EventPublisher) bool {
	_, isNoop := pub.(*NoopPublisher)
	return !isNoop
}
