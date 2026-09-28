-- V31: reportes de cumplimiento (HU "Exportar reporte de cumplimiento en PDF")
--
-- Un Report congela los resultados de un análisis COMPLETED en content_json
-- (secretos ya enmascarados) y guarda su SHA-256 en checksum. Los exportadores
-- (PDF, y en el futuro SARIF) renderizan siempre desde content_json, nunca desde
-- las tablas vivas, y rechazan la exportación si el checksum ya no coincide.
--
-- analysis_id / generated_by usan ON DELETE SET NULL: el reporte es evidencia de
-- auditoría y debe sobrevivir aunque se borre el repositorio o el usuario.

CREATE TABLE reports (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id   UUID REFERENCES analyses(id) ON DELETE SET NULL,
    status        VARCHAR(20) NOT NULL,
    content_json  TEXT NOT NULL,
    checksum      VARCHAR(64) NOT NULL,
    generated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    generated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_reports_status CHECK (status IN ('GENERATED'))
);

CREATE INDEX idx_reports_analysis_id ON reports(analysis_id);
