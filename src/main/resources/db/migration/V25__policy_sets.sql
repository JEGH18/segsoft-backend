-- V25: Policy Sets -- catálogo reutilizable de conjuntos de políticas.
-- Distinto de policy_selections (que es la selección de políticas de UN
-- repositorio, sin nombre ni reutilización): un Policy Set se crea una vez,
-- con nombre y descripción, se edita y se archiva, para estandarizar
-- perfiles de cumplimiento reutilizables entre repositorios.

CREATE TABLE policy_sets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(200) NOT NULL,
    description   TEXT,
    status        VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    version       INTEGER      NOT NULL DEFAULT 1,
    created_by    UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_sets_status ON policy_sets (status);

CREATE TABLE policy_set_items (
    policy_set_id UUID NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
    policy_id     UUID NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
    PRIMARY KEY (policy_set_id, policy_id)
);

CREATE INDEX idx_policy_set_items_policy_id ON policy_set_items (policy_id);

-- Traza qué policy_selection de un repositorio se originó a partir de un
-- Policy Set, para poder bloquear el archivado (escenario 5 de la HU) cuando
-- ese repositorio tiene un análisis QUEUED/RUNNING en curso.
ALTER TABLE policy_selections
    ADD COLUMN policy_set_id UUID REFERENCES policy_sets(id) ON DELETE SET NULL;

CREATE INDEX idx_policy_selections_policy_set_id ON policy_selections (policy_set_id);

-- Reutiliza policy_audit_log para el historial de Policy Sets (mismo patrón
-- que policies) en vez de crear una tabla de auditoría nueva.
ALTER TABLE policy_audit_log
    ADD COLUMN policy_set_id UUID REFERENCES policy_sets(id) ON DELETE SET NULL;

CREATE INDEX idx_policy_audit_log_policy_set_id ON policy_audit_log (policy_set_id);
