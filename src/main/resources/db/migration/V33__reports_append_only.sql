-- V33: reports es append-only.
--
-- Un reporte es evidencia de auditoría: una vez generado no se modifica ni se
-- borra. La entidad JPA es @Immutable y este trigger lo impone también en la
-- base de datos, para cualquier cliente.
--
-- Única excepción: las FK analysis_id y generated_by son ON DELETE SET NULL,
-- así que borrar un análisis/repositorio o un usuario pone esas columnas en
-- NULL. Se permite exclusivamente ese cambio (el contenido congelado ya
-- incluye ambos datos); cualquier otro UPDATE, y todo DELETE, se rechaza.
-- La detección por checksum sigue siendo la segunda línea de defensa frente a
-- quien deshabilite el trigger.

CREATE OR REPLACE FUNCTION reports_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'reports es append-only: no se permite eliminar el reporte %', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;

    IF NEW.id = OLD.id
       AND NEW.content = OLD.content
       AND NEW.checksum = OLD.checksum
       AND NEW.status = OLD.status
       AND NEW.generated_at = OLD.generated_at
       AND (NEW.analysis_id IS NOT DISTINCT FROM OLD.analysis_id OR NEW.analysis_id IS NULL)
       AND (NEW.generated_by IS NOT DISTINCT FROM OLD.generated_by OR NEW.generated_by IS NULL) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'reports es append-only: no se permite modificar el reporte %', OLD.id
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_reports_append_only
    BEFORE UPDATE OR DELETE ON reports
    FOR EACH ROW EXECUTE FUNCTION reports_append_only();

-- Histórico por repositorio (GET /api/v1/reports?repositoryId=...): se lee del
-- contenido congelado, así sobrevive aunque el análisis se haya borrado.
CREATE INDEX idx_reports_repository_id ON reports ((content -> 'metadata' ->> 'repositoryId'));
CREATE INDEX idx_reports_generated_at ON reports (generated_at DESC);
