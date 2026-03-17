CREATE TABLE IF NOT EXISTS auth_users (
    user_id     VARCHAR(64)  PRIMARY KEY,
    provider    VARCHAR(32)  NOT NULL,
    provider_user_id VARCHAR(128) NOT NULL,
    email       VARCHAR(255) NULL,
    created_at  TIMESTAMPTZ  DEFAULT NOW(),

    CONSTRAINT uq_auth_users_provider UNIQUE (provider, provider_user_id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGSERIAL PRIMARY KEY,

    user_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    token_hash TEXT NOT NULL,

    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NULL,

    revoked BOOLEAN NOT NULL DEFAULT FALSE,

    user_agent TEXT NULL,
    ip_address VARCHAR(64) NULL,

    created_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT uq_refresh_tokens_user_device UNIQUE (user_id, device_id)
);

CREATE INDEX idx_refresh_tokens_user
ON refresh_tokens(user_id);

CREATE INDEX idx_refresh_tokens_active
ON refresh_tokens(user_id)
WHERE revoked = false AND expires_at > NOW();

CREATE INDEX idx_refresh_tokens_expires
ON refresh_tokens(expires_at);