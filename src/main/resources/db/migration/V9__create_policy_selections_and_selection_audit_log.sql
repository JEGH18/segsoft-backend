-- V10: selección de políticas por repositorio y auditoría de cambios (HU-08 + HU-06)

CREATE TABLE policy_selections (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id        UUID UNIQUE NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    selected_policy_ids  JSONB NOT NULL DEFAULT '[]'::jsonb,
    version              INTEGER NOT NULL DEFAULT 0,
    created_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_selections_repository_id ON policy_selections (repository_id);

CREATE TABLE IF NOT EXISTS selection_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id   UUID REFERENCES repositories(id) ON DELETE CASCADE,
    action          VARCHAR(50) NOT NULL,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    username        VARCHAR(100),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_selection_audit_log_repository_id
    ON selection_audit_log (repository_id);
CREATE INDEX IF NOT EXISTS idx_selection_audit_log_timestamp
    ON selection_audit_log (timestamp);
