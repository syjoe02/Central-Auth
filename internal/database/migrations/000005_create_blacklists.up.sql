-- Global admin blacklist for USER (kratos_id), JTI, and SERVICE_KEY targets.
-- Distinct from blacklisted_sessions (BFF session revocation); this table drives
-- fan-out to downstream services via the blacklist-sync Kafka topic.
CREATE TABLE blacklists (
    id           BIGSERIAL PRIMARY KEY,
    target_type  VARCHAR(32)              NOT NULL,
    target_value TEXT                     NOT NULL,
    reason       TEXT,
    created_at   TIMESTAMPTZ              NOT NULL DEFAULT NOW(),
    UNIQUE (target_type, target_value)
);

-- Fast point-lookup on every L1 cache miss (target_type + target_value).
CREATE INDEX idx_blacklists_lookup ON blacklists (target_type, target_value);
