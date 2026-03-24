package middleware

import (
	"time"

	"central-auth/internal/kafka"

	"github.com/gin-gonic/gin"
)

// KafkaAccessLogMiddleware publishes an AccessLogEvent to Kafka after every
// request. Publishing is asynchronous and non-blocking: it never adds latency
// to the HTTP response path.
//
// user_id is read from the "kratosID" context key, which any downstream
// middleware or handler may populate via c.Set("kratosID", id). It falls back
// to an empty string for unauthenticated or S2S requests.
//
// path uses c.FullPath() (the route template, e.g. "/bff/whoami") rather than
// the raw URL to prevent unbounded cardinality in the Kafka topic.
func KafkaAccessLogMiddleware(pub kafka.EventPublisher) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// Extract user identity. The "kratosID" key is set by BFF handlers or
		// BFFSessionMiddleware after session resolution. Empty for S2S routes.
		userID := ""
		if v, exists := c.Get("kratosID"); exists {
			if id, ok := v.(string); ok {
				userID = id
			}
		}

		path := c.FullPath()
		if path == "" {
			path = "unmatched"
		}

		pub.Publish(kafka.AccessLogEvent{
			Path:       path,
			StatusCode: c.Writer.Status(),
			LatencyMs:  time.Since(start).Milliseconds(),
			UserID:     userID,
			Timestamp:  start.UTC().Format(time.RFC3339Nano),
		})
	}
}
