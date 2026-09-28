-- V20: ciclo de vida de políticas (HU PDGSEGSOFT-24)
-- version y weight ya existían desde V2. Aquí:
--  1) convertimos applicability de jsonb a text (mismo motivo que V16: el
--     driver JDBC rechaza insertar un String Java en una columna jsonb sin
--     cast explícito -- el AttributeConverter de Hibernate serializa como String).
--  2) creamos policy_version_history para guardar el snapshot de cada
--     versión anterior antes de aplicar un PATCH.

ALTER TABLE policies
    ALTER COLUMN applicability TYPE text USING applicability::text;

CREATE TABLE policy_version_history (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id     UUID         NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version       INTEGER      NOT NULL,
    name          VARCHAR(200) NOT NULL,
    description   TEXT,
    category      VARCHAR(50)  NOT NULL,
    framework     VARCHAR(50)  NOT NULL,
    control_id    VARCHAR(100),
    status        VARCHAR(20)  NOT NULL,
    weight        INTEGER      NOT NULL,
    applicability TEXT,
    changed_by    UUID         REFERENCES users(id) ON DELETE SET NULL,
    changed_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_version_history_policy_id ON policy_version_history (policy_id);
CREATE INDEX idx_policy_version_history_changed_at ON policy_version_history (changed_at);
