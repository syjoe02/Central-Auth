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
			path = c.Request.URL.Path
		}

		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		elapsed := time.Since(start).Seconds()

		metrics.HTTPRequests.WithLabelValues(c.Request.Method, path, status).Inc()
		metrics.HTTPDuration.WithLabelValues(c.Request.Method, path).Observe(elapsed)
	}
}
