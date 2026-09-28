-- V2: tabla de políticas de seguridad

CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    category        VARCHAR(50)  NOT NULL,
    framework       VARCHAR(50)  NOT NULL,
    control_id      VARCHAR(100),
    status          VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    version         INTEGER      NOT NULL DEFAULT 1,
    weight          INTEGER      NOT NULL DEFAULT 50
                        CHECK (weight BETWEEN 1 AND 100),
    applicability   JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by      UUID         REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_policies_category  ON policies (category);
CREATE INDEX idx_policies_framework ON policies (framework);
CREATE INDEX idx_policies_status    ON policies (status);
