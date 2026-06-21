package config

// ResilienceConfig holds circuit-breaker tuning parameters loaded from env vars.
// All values have safe defaults suitable for production.
type ResilienceConfig struct {
	// FailureThreshold is the number of consecutive infrastructure errors that
	// trip the circuit from CLOSED to OPEN. Default: 5.
	FailureThreshold int
	// ProbeBaseSeconds is the initial OPEN→HALF-OPEN backoff in seconds.
	// The interval doubles on each failed probe, capped at ProbeMaxSeconds. Default: 30.
	ProbeBaseSeconds int
	// ProbeMaxSeconds caps the maximum probe backoff. Default: 300 (5 min).
	ProbeMaxSeconds int
	// JitterPct is the percentage of the computed backoff added as random jitter
	// (±JitterPct%). Prevents thundering-herd at probe expiry. Default: 15.
	JitterPct int
}

// LoadResilienceConfig reads circuit-breaker config from environment variables.
func LoadResilienceConfig() ResilienceConfig {
	return ResilienceConfig{
		FailureThreshold: envInt("REDIS_CB_FAILURE_THRESHOLD", 5),
		ProbeBaseSeconds: envInt("REDIS_CB_PROBE_BASE_SECONDS", 60),
		ProbeMaxSeconds:  envInt("REDIS_CB_PROBE_MAX_SECONDS", 300),
		JitterPct:        envInt("REDIS_CB_JITTER_PCT", 15),
	}
}
