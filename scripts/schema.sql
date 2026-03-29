-- =============================================================================
-- Central-Auth Application Database Schema
-- =============================================================================
-- This database (central_auth) stores ONLY application-level data.
-- Identity data lives in the Kratos database (managed by Ory Kratos).
-- OAuth2 token data lives in the Hydra database (managed by Ory Hydra).
-- =============================================================================

-- device_sessions tracks active and historical login sessions per Kratos identity.
-- It is an AUDIT LOG — Hydra owns the actual token lifecycle.
-- kratosID is the Ory Kratos identity.id (UUID string).
CREATE TABLE IF NOT EXISTS device_sessions (
    id           BIGSERIAL    PRIMARY KEY,
    kratos_id    VARCHAR(64)  NOT NULL,
    device_id    VARCHAR(128) NOT NULL,

    -- hydra_jti is the Hydra access token JTI at time of login; used for correlation only.
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
