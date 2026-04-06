package metrics

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

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

	// BFF session metrics.

	BFFSessionsCreated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_bff_sessions_created_total",
		Help: "Total BFF sessions created (logins).",
	})

	BFFSessionsDestroyed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_bff_sessions_destroyed_total",
		Help: "Total BFF sessions destroyed (logouts).",
	})

	// BFFBlacklistChecks counts blacklist lookups; label "result" is "hit" or "miss".
	BFFBlacklistChecks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "central_auth_bff_blacklist_checks_total",
			Help: "Total BFF blacklist checks by result (hit/miss).",
		},
		[]string{"result"},
	)

	// BFFTokenRefreshes counts proactive Hydra token refreshes; label "result" is "ok" or "error".
	BFFTokenRefreshes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "central_auth_bff_token_refreshes_total",
			Help: "Total proactive Hydra token refreshes triggered by the BFF.",
		},
		[]string{"result"},
	)

	// BFFJWKSDeprecatedKidUsed increments each time a token is validated using
	// a key from the previous JWKS generation (during a rotation grace period).
	BFFJWKSDeprecatedKidUsed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_bff_jwks_deprecated_kid_used_total",
		Help: "Times a JWT was validated with a key from the previous JWKS generation.",
	})

	BFFCSRFRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_bff_csrf_rejected_total",
		Help: "Total requests rejected by the CSRF middleware.",
	})

	// KafkaEventsDropped counts access-log events dropped because the internal
	// producer channel was full (Kafka slow or unreachable).
	KafkaEventsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_kafka_events_dropped_total",
		Help: "Total access-log events dropped due to full Kafka producer channel.",
	})

	// KafkaAuthSessionsPublished counts AuthSessionEvents successfully written to Kafka.
	KafkaAuthSessionsPublished = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_kafka_auth_sessions_published_total",
		Help: "Total AuthSessionEvent messages successfully written to Kafka at login.",
	})

	// KafkaAuthSessionsDropped counts AuthSessionEvents dropped because the authCh
	// channel was full. Separate from KafkaEventsDropped (access logs) because a
	// dropped auth-session event is a lost audit record — a distinct SLO signal.
	KafkaAuthSessionsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_kafka_auth_sessions_dropped_total",
		Help: "Total AuthSessionEvent messages dropped due to full auth producer channel.",
	})

	// KafkaConsumerErrors counts consumer-side processing failures by operation.
	// label "operation": "fetch", "unmarshal", "parse_timestamp", "save_device_session"
	KafkaConsumerErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "central_auth_kafka_consumer_errors_total",
			Help: "Total Kafka consumer processing errors by operation.",
		},
		[]string{"operation"},
	)

	// KafkaConsumerSkipped counts messages on the access-logs topic that were not
	// AuthSessionEvents (e.g. AccessLogEvents). Expected to be the majority of
	// traffic; useful for verifying the consumer is running and filtering correctly.
	KafkaConsumerSkipped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_kafka_consumer_skipped_total",
		Help: "Total non-auth-session messages skipped by the DeviceSessionConsumer.",
	})

	// KafkaConsumerLag is the current estimated consumer group lag for the
	// device-session consumer (sampled every 10s from reader.Stats().Lag).
	KafkaConsumerLag = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "central_auth_kafka_consumer_lag",
		Help: "Current Kafka consumer group lag (messages behind) for the device-session consumer.",
	})
)

func RegisterPGXStats(dbName string, pool *pgxpool.Pool) {
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name:        "go_pgx_pool_connections_open",
			Help:        "The number of established connections both in use and idle.",
			ConstLabels: prometheus.Labels{"db_name": dbName},
		},
		func() float64 { return float64(pool.Stat().TotalConns()) },
	))

	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name:        "go_pgx_pool_connections_in_use",
			Help:        "The number of connections currently in use.",
			ConstLabels: prometheus.Labels{"db_name": dbName},
		},
		func() float64 { return float64(pool.Stat().AcquiredConns()) },
	))

	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name:        "go_pgx_pool_connections_idle",
			Help:        "The number of idle connections.",
			ConstLabels: prometheus.Labels{"db_name": dbName},
		},
		func() float64 { return float64(pool.Stat().IdleConns()) },
	))
}

func init() {
	prometheus.MustRegister(
		HTTPRequests,
		HTTPDuration,
		AuthOps,
		RedisOps,
		PostgresOps,
		OryOps,
		BFFSessionsCreated,
		BFFSessionsDestroyed,
		BFFBlacklistChecks,
		BFFTokenRefreshes,
		BFFJWKSDeprecatedKidUsed,
		BFFCSRFRejected,
		KafkaEventsDropped,
		KafkaAuthSessionsPublished,
		KafkaAuthSessionsDropped,
		KafkaConsumerErrors,
		KafkaConsumerSkipped,
		KafkaConsumerLag,
	)
}
