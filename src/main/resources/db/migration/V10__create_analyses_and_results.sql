-- V5: análisis de cumplimiento y resultados

CREATE TABLE analyses (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id    UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    status           VARCHAR(20) NOT NULL,
    rules_total      INTEGER NOT NULL DEFAULT 0,
    rules_executed   INTEGER NOT NULL DEFAULT 0,
    progress         NUMERIC(5,2) NOT NULL DEFAULT 0,
    error_message    TEXT,
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    cancelled_at     TIMESTAMPTZ,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_analyses_repository_id ON analyses(repository_id);
CREATE INDEX idx_analyses_status ON analyses(status);
CREATE UNIQUE INDEX uq_analyses_active_per_repository
    ON analyses(repository_id)
    WHERE status IN ('QUEUED', 'RUNNING');

CREATE TABLE analysis_snapshots (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id    UUID NOT NULL UNIQUE REFERENCES analyses(id) ON DELETE CASCADE,
    snapshot_json  JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id       UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    repository_id     UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    policy_id         UUID REFERENCES policies(id) ON DELETE SET NULL,
    rule_id           UUID REFERENCES rules(id) ON DELETE SET NULL,
    severity          VARCHAR(20) NOT NULL,
    category          VARCHAR(100) NOT NULL,
    file_path         TEXT NOT NULL,
    line_number       INTEGER,
    evidence_snippet  TEXT,
    file_sha256       VARCHAR(64),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_analysis_id ON findings(analysis_id);
CREATE INDEX idx_findings_policy_id ON findings(policy_id);
CREATE INDEX idx_findings_severity ON findings(severity);

CREATE TABLE policy_results (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id              UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    policy_id                UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    status                   VARCHAR(30) NOT NULL,
    findings_count           INTEGER NOT NULL DEFAULT 0,
    high_or_critical_count   INTEGER NOT NULL DEFAULT 0,
    low_or_medium_count      INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (analysis_id, policy_id)
);

CREATE INDEX idx_policy_results_analysis_id ON policy_results(analysis_id);

CREATE TABLE rule_execution_errors (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id    UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    policy_id      UUID REFERENCES policies(id) ON DELETE SET NULL,
    rule_id        UUID REFERENCES rules(id) ON DELETE SET NULL,
    error_code     VARCHAR(50) NOT NULL,
    message        TEXT NOT NULL,
    file_path      TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rule_execution_errors_analysis_id ON rule_execution_errors(analysis_id);
