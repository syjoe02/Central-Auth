package resilience

import "github.com/prometheus/client_golang/prometheus"

var (
	// CBState tracks the current circuit breaker state: 0=closed, 1=open, 2=half-open.
	CBState = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "central_auth_redis_circuit_breaker_state",
		Help: "Redis circuit breaker state: 0=closed 1=open 2=half-open.",
	})

	// CBTripsTotal counts how many times the circuit has tripped from CLOSED to OPEN.
	CBTripsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "central_auth_redis_circuit_breaker_trips_total",
		Help: "Total number of times the Redis circuit breaker has tripped open.",
	})

	// L1CacheHits counts L1 in-process cache hits, labelled by store (blacklist/session/device).
	L1CacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "central_auth_l1_cache_hits_total",
		Help: "L1 in-process cache hits by store.",
	}, []string{"store"})

	// L1CacheMisses counts L1 in-process cache misses, labelled by store.
	L1CacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "central_auth_l1_cache_misses_total",
		Help: "L1 in-process cache misses by store.",
	}, []string{"store"})

	// PgFallbackTotal counts PostgreSQL fallback queries, labelled by operation.
	PgFallbackTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "central_auth_pg_fallback_total",
		Help: "PostgreSQL fallback queries by operation (used when Redis circuit is open).",
	}, []string{"operation"})
)

func init() {
	prometheus.MustRegister(CBState, CBTripsTotal, L1CacheHits, L1CacheMisses, PgFallbackTotal)
}
