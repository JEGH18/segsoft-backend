ALTER TABLE policy_selections
    ADD COLUMN source VARCHAR(255) NOT NULL DEFAULT 'MANUAL';

-- Backfill: selections already linked to a Policy Set (via the existing
-- policy_set_id FK) get a proper source string instead of the default
-- 'MANUAL', using that set's current version as the best available snapshot.
UPDATE policy_selections ps
SET source = 'POLICY_SET:' || pset.id || ':' || pset.version
FROM policy_sets pset
WHERE ps.policy_set_id = pset.id;
