-- V5: tabla de reglas técnicas verificables

CREATE TABLE rules (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id      UUID        NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    type           VARCHAR(30) NOT NULL
                       CHECK (type IN ('PATTERN_REGEX','AST_QUERY','CONFIG_CHECK','DEPENDENCY_CHECK')),
    payload        JSONB       NOT NULL,
    target_artifact VARCHAR(100),
    languages      JSONB       NOT NULL DEFAULT '[]',
    severity       VARCHAR(10) NOT NULL
                       CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    cwe_id         VARCHAR(20),
    category       VARCHAR(50),
    status         VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                       CHECK (status IN ('ACTIVE','ARCHIVED')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rules_policy_id ON rules (policy_id);
CREATE INDEX idx_rules_status    ON rules (status);
CREATE INDEX idx_rules_type      ON rules (type);
