-- V21: tokens de larga duración para pipelines CI/CD, distintos del JWT de
-- sesión web. Solo se guarda el hash -- el valor en claro solo existe en el
-- momento de creación y nunca se persiste ni se puede recuperar después.

CREATE TABLE api_tokens (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(150) NOT NULL,
    token_hash  VARCHAR(64)  NOT NULL UNIQUE,
    created_by  UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_tokens_created_by ON api_tokens (created_by);
