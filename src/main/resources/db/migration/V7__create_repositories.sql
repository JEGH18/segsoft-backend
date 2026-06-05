-- V7: tabla de repositorios para análisis de cumplimiento (HU-04 + HU-05)

CREATE TABLE repositories (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status           VARCHAR(30)  NOT NULL DEFAULT 'UPLOADING'
                         CHECK (status IN ('UPLOADING','READY_FOR_ANALYSIS','ANALYZING','ARCHIVED','EXPIRED','FAILED')),
    inventory_status VARCHAR(30)  NOT NULL DEFAULT 'PENDING'
                         CHECK (inventory_status IN ('PENDING','RUNNING','DONE','FAILED')),
    source_type      VARCHAR(20)  NOT NULL DEFAULT 'ZIP'
                         CHECK (source_type IN ('ZIP','GIT')),
    original_name    VARCHAR(500) NOT NULL,
    git_url          VARCHAR(1000),
    branch           VARCHAR(200),
    path_in_sandbox  VARCHAR(500),
    sha256_archive   VARCHAR(64),
    file_count       INTEGER,
    excluded_count   BIGINT       NOT NULL DEFAULT 0,
    error_message    TEXT,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ  NOT NULL DEFAULT now() + INTERVAL '24 hours'
);

CREATE INDEX idx_repositories_user_id      ON repositories (user_id);
CREATE INDEX idx_repositories_status       ON repositories (status);
CREATE INDEX idx_repositories_inv_status   ON repositories (inventory_status);
CREATE INDEX idx_repositories_expires_at   ON repositories (expires_at);
