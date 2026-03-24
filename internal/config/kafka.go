package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// KafkaConfig holds configuration for the Kafka access-log producer.
type KafkaConfig struct {
	Brokers      []string
	Topic        string
	ChannelSize  int
	WriteTimeout time.Duration
	IsProduction bool
}

// LoadKafkaConfig reads Kafka configuration from environment variables.
//
//   - KAFKA_BROKERS  — comma-separated broker addresses (default "kafka:9092")
//   - KAFKA_TOPIC    — topic name (default "access-logs")
//   - KAFKA_CHANNEL_SIZE — internal buffer depth, clamped [64, 65536] (default 4096)
//   - IS_PRODUCTION  — "true" enables fail-fast on broker connection failure
func LoadKafkaConfig() KafkaConfig {
	brokersRaw := os.Getenv("KAFKA_BROKERS")
	if brokersRaw == "" {
		brokersRaw = "kafka:9092"
	}
	brokers := []string{}
	for _, b := range strings.Split(brokersRaw, ",") {
		if t := strings.TrimSpace(b); t != "" {
			brokers = append(brokers, t)
		}
	}

	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" {
		topic = "access-logs"
	}

	channelSize := 4096
	if v := os.Getenv("KAFKA_CHANNEL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			switch {
			case n < 64:
				log.Printf("[WARN] KAFKA_CHANNEL_SIZE %d below minimum 64; using 64", n)
				channelSize = 64
			case n > 65536:
				log.Printf("[WARN] KAFKA_CHANNEL_SIZE %d above maximum 65536; using 65536", n)
				channelSize = 65536
			default:
				channelSize = n
			}
		}
	}

	return KafkaConfig{
		Brokers:      brokers,
		Topic:        topic,
		ChannelSize:  channelSize,
		WriteTimeout: 5 * time.Second,
		IsProduction: strings.EqualFold(os.Getenv("IS_PRODUCTION"), "true"),
	}
}
