-- V37: los tokens de API pasan a ser de cada usuario (antes solo los creaba un
-- SECURITY_ADMIN y no autenticaban nada). Cada token pertenece a quien lo creó,
-- autentica como ese usuario y vence.
--
-- token_prefix: los primeros caracteres del token en claro, para reconocerlo en
--               una lista sin poder usarlo.
-- expires_at:   después de esta fecha el token deja de autenticar.
-- last_used_at: última vez que autenticó una petición (se actualiza como mucho
--               una vez por minuto).

ALTER TABLE api_tokens
    ADD COLUMN token_prefix VARCHAR(16),
    ADD COLUMN expires_at   TIMESTAMPTZ,
    ADD COLUMN last_used_at TIMESTAMPTZ;

-- Los tokens creados antes de V37 no autenticaban; sin fecha de vencimiento
-- quedan vencidos desde ya, y sin dueño no tienen a quién representar.
UPDATE api_tokens SET expires_at = now() WHERE expires_at IS NULL;
DELETE FROM api_tokens WHERE created_by IS NULL;

ALTER TABLE api_tokens
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN created_by SET NOT NULL;

-- Si se borra el usuario, sus tokens se van con él (antes quedaban huérfanos).
ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_created_by_fkey;
ALTER TABLE api_tokens
    ADD CONSTRAINT api_tokens_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE;
