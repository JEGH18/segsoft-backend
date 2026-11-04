-- V35: enlaces de un solo uso para desbloquear una cuenta bloqueada por intentos fallidos.
-- Se envían al correo verificado de la cuenta y vencen cuando termina el bloqueo. Solo se
-- guarda el SHA-256 del token.

CREATE TABLE account_unlock_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_account_unlock_tokens_user ON account_unlock_tokens (user_id);
CREATE INDEX idx_account_unlock_tokens_expires ON account_unlock_tokens (expires_at);
