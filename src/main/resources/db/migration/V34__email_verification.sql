-- V34: correo único por cuenta y verificación del correo en el registro.
-- El correo es opcional en la tabla: las cuentas de SEGSOFT_ACCOUNTS y las registradas antes
-- de esta migración no tienen. Solo las cuentas con correo sin verificar no pueden iniciar sesión.

ALTER TABLE users
    ADD COLUMN email             VARCHAR(254),
    ADD COLUMN email_verified_at TIMESTAMPTZ;

-- Único sin distinguir mayúsculas; también cubre dos registros simultáneos con el mismo correo.
CREATE UNIQUE INDEX ux_users_email_lower ON users (lower(email)) WHERE email IS NOT NULL;

-- Enlaces de verificación de un solo uso. Solo se guarda el SHA-256 del token: el valor en claro
-- solo existe en el correo enviado.
CREATE TABLE email_verification_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_email_verification_tokens_user ON email_verification_tokens (user_id);
CREATE INDEX idx_email_verification_tokens_expires ON email_verification_tokens (expires_at);
