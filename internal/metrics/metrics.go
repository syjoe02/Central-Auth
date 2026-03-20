package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	HTTPRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "central_auth_http_requests_total",
			Help: "Total HTTP requests by method, path, and status code.",
		},
		[]string{"method", "path", "status"},
	)

	HTTPDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "central_auth_http_request_duration_seconds",
			Help:    "HTTP request latency by method and path.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	AuthOps = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "central_auth_auth_operations_total",
			Help: "Total auth operations (login, refresh, logout) by operation and result.",
		},
		[]string{"operation", "result"},
	)

	RedisOps = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "central_auth_redis_operation_duration_seconds",
			Help:    "Redis operation latency by operation name.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	PostgresOps = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "central_auth_postgres_operation_duration_seconds",
			Help:    "Postgres operation latency by operation name.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	// OryOps tracks latency for Ory Kratos and Ory Hydra API calls.
	OryOps = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "central_auth_ory_operation_duration_seconds",
			Help:    "Ory Kratos/Hydra API call latency by operation name.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)
)

func init() {
	prometheus.MustRegister(
		HTTPRequests,
		HTTPDuration,
		AuthOps,
		RedisOps,
		PostgresOps,
		OryOps,
	)
}
