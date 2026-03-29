package middleware

import (
	"strconv"
	"time"

	"central-auth/internal/metrics"

	"github.com/gin-gonic/gin"
)

// PrometheusMiddleware records HTTP request counts and latencies.
func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			// Security fix M-6: using the raw URL path as a label causes unbounded
			// Prometheus cardinality — every unique scanner probe creates a new
			// time series that is never garbage-collected. Use a fixed label instead.
			path = "unmatched"
		}

		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		elapsed := time.Since(start).Seconds()

		metrics.HTTPRequests.WithLabelValues(c.Request.Method, path, status).Inc()
		metrics.HTTPDuration.WithLabelValues(c.Request.Method, path).Observe(elapsed)
	}
}
