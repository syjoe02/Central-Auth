-- Migration 001: blacklisted_sessions
-- PostgreSQL fallback table for the session blacklist.
-- Consulted only when the Redis circuit breaker is OPEN and the L1 cache misses.
-- Redis remains the primary store; this table provides durability during outages.

CREATE TABLE IF NOT EXISTS blacklisted_sessions (
    session_id TEXT        PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Allows the BlacklistPgRepository.DeleteExpired maintenance query to run efficiently.
CREATE INDEX IF NOT EXISTS idx_blacklisted_sessions_expires_at
    ON blacklisted_sessions(expires_at);
