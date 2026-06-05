ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(50),
    ADD COLUMN IF NOT EXISTS suggested_action TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_analysis_severity
    ON findings(analysis_id, severity);

CREATE INDEX IF NOT EXISTS idx_findings_category
    ON findings(category);
