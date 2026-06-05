-- V5: tabla de archivos inventariados por repositorio

CREATE TABLE repository_files (
    id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id   UUID          NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path            VARCHAR(1000) NOT NULL,
    language        VARCHAR(50)   NOT NULL DEFAULT 'unknown',
    artifact_type   VARCHAR(50)   NOT NULL DEFAULT 'SOURCE_CODE',
    size_bytes      BIGINT        NOT NULL DEFAULT 0,
    sha256          VARCHAR(64)   NOT NULL
);

CREATE INDEX idx_repo_files_repository_id  ON repository_files (repository_id);
CREATE INDEX idx_repo_files_language       ON repository_files (repository_id, language);
CREATE INDEX idx_repo_files_artifact_type  ON repository_files (repository_id, artifact_type);
