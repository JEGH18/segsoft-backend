-- V4: restricción de unicidad en policies + tabla de auditoría de políticas

ALTER TABLE policies
    ADD CONSTRAINT uq_policies_name_framework UNIQUE (name, framework);

CREATE TABLE policy_audit_log (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    action        VARCHAR(50) NOT NULL,
    policy_id     UUID        REFERENCES policies(id) ON DELETE SET NULL,
    username      VARCHAR(100),
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload       JSONB
);

CREATE INDEX idx_policy_audit_log_policy_id  ON policy_audit_log (policy_id);
CREATE INDEX idx_policy_audit_log_timestamp  ON policy_audit_log (timestamp);
