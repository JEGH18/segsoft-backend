-- V3: account locking fields for brute-force protection + refresh token blacklist

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until    TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS refresh_token_blacklist (
    token_hash VARCHAR(64)  PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rtb_expires_at ON refresh_token_blacklist (expires_at);

-- Seed admin user (password: admin123 — argon2id, m=16384,t=2,p=1)
INSERT INTO users (username, password_hash)
VALUES (
    'admin',
    '$argon2id$v=19$m=16384,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaasfNcbz0L+GE7zfw'
)
ON CONFLICT (username) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'SECURITY_ADMIN'
ON CONFLICT DO NOTHING;
