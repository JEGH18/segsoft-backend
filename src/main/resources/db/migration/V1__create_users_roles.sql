-- V1: usuarios, roles y auditoría de autenticación

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    enabled       BOOLEAN DEFAULT true,
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE roles (
    id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE auth_audit_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50)  NOT NULL,
    username   VARCHAR(100),
    ip_address VARCHAR(45),
    timestamp  TIMESTAMPTZ  DEFAULT now(),
    details    JSONB
);

CREATE INDEX idx_auth_audit_log_username  ON auth_audit_log (username);
CREATE INDEX idx_auth_audit_log_timestamp ON auth_audit_log (timestamp);

INSERT INTO roles (name) VALUES ('DEVELOPER'), ('AUDITOR'), ('SECURITY_ADMIN');
