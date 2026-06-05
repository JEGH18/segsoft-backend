-- V16: convierte a text todas las columnas jsonb que Hibernate escribe como varchar
-- Mismo problema que V15 (selected_policy_ids). El driver JDBC rechaza insertar
-- un String Java en una columna de tipo jsonb sin cast explícito.

ALTER TABLE analysis_snapshots
    ALTER COLUMN snapshot_json TYPE text USING snapshot_json::text;

ALTER TABLE rules
    ALTER COLUMN payload    TYPE text USING payload::text;

ALTER TABLE rules
    ALTER COLUMN languages  TYPE text USING languages::text;
