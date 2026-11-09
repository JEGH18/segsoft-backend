-- V36: recuperación de contraseña.
--
-- password_reset_tokens: enlaces de un solo uso para elegir una contraseña nueva. Se envían al
-- correo verificado de la cuenta y vencen a los 30 minutos. Solo se guarda el SHA-256 del token.
--
-- users.token_version: va dentro de los tokens de acceso y de renovación. Cambiar la contraseña
-- lo incrementa y los tokens emitidos con el número anterior dejan de servir: así se cierran todas
-- las sesiones abiertas, incluida la de quien la hubiera robado.

ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE password_reset_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens (user_id);
CREATE INDEX idx_password_reset_tokens_expires ON password_reset_tokens (expires_at);
