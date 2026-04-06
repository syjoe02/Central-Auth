-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction.
-- The no-transaction directive instructs golang-migrate to skip the implicit
-- BEGIN/COMMIT wrapper for this migration file.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_sessions_kratos_issued
    ON device_sessions (kratos_id, issued_at DESC);
