-- V22: policy_audit_log quedó sin user_id (solo username), a diferencia de
-- selection_audit_log que ya guarda ambos. Alinea la trazabilidad: se
-- necesita poder ver qué usuario (con su id, no solo el nombre de usuario en
-- texto) creó/editó/archivó/restauró cada política.

ALTER TABLE policy_audit_log
    ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE SET NULL;

UPDATE policy_audit_log pal
SET user_id = u.id
FROM users u
WHERE u.username = pal.username
  AND pal.user_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_policy_audit_log_user_id ON policy_audit_log (user_id);
