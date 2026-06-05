-- V15: cambia selected_policy_ids de jsonb a text
-- El AttributeConverter en Java serializa/deserializa como String.
-- PostgreSQL rechaza insertar varchar en jsonb sin cast explícito desde JDBC.

ALTER TABLE policy_selections
    ALTER COLUMN selected_policy_ids TYPE text USING selected_policy_ids::text;
