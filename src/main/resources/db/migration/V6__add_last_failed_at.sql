-- V6: ventana temporal para bloqueo de cuenta (10 minutos entre intentos fallidos)

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_failed_at TIMESTAMPTZ;
