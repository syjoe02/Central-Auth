-- =============================================================================
-- One-time migration: legacy schema → Ory-backed schema
-- =============================================================================
-- Run this ONCE against the central_auth database AFTER Kratos and Hydra have
-- been deployed and all existing Kratos identities have been created.
--
-- WARNING: This migration drops auth_users and refresh_tokens.
-- All existing JWT sessions become invalid after this migration is applied.
-- Users must re-authenticate.
--
-- Steps:
--   1. Take a full database backup.
--   2. Apply all pending Kratos migrations (kratos migrate sql).
--   3. Apply all pending Hydra migrations (hydra migrate sql).
--   4. Run this script against the central_auth database.
--   5. Deploy the new Go service binary.
-- =============================================================================

BEGIN;

-- Step 1: Create the new device_sessions table if it doesn't exist yet.
CREATE TABLE IF NOT EXISTS device_sessions (
    id           BIGSERIAL    PRIMARY KEY,
    kratos_id    VARCHAR(64)  NOT NULL,
    device_id    VARCHAR(128) NOT NULL,
    hydra_jti    VARCHAR(256) NULL,
    issued_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ  NULL,
    revoked      BOOLEAN      NOT NULL DEFAULT FALSE,
    user_agent   TEXT         NULL,
    ip_address   VARCHAR(64)  NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_device_sessions_kratos_device UNIQUE (kratos_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_device_sessions_kratos
    ON device_sessions(kratos_id);
CREATE INDEX IF NOT EXISTS idx_device_sessions_active
    ON device_sessions(kratos_id)
    WHERE revoked = false;

-- Step 2: Migrate non-revoked device sessions from refresh_tokens.
-- NOTE: user_id from the legacy table is used as kratos_id.
-- This is only valid if user_id values were already Kratos identity UUIDs.
-- If user_id values are NOT Kratos UUIDs, this INSERT should be skipped
-- and device_sessions will be populated fresh as users log in.
INSERT INTO device_sessions (
    kratos_id,
    device_id,
    issued_at,
    last_used_at,
    revoked,
    user_agent,
    ip_address
)
SELECT
    user_id,
    device_id,
    issued_at,
    last_used_at,
    revoked,
    user_agent,
    ip_address
FROM refresh_tokens
ON CONFLICT (kratos_id, device_id) DO NOTHING;

-- Step 3: Drop legacy tables (identity data now owned by Kratos).
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS auth_users;

COMMIT;

-- Verification queries (run manually after migration):
-- SELECT count(*) FROM device_sessions;
-- \d+ device_sessions
