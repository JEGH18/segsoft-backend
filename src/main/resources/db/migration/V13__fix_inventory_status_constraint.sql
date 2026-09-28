-- V13: alinea el check constraint de inventory_status con el enum Java
-- El enum InventoryStatus tiene: PENDING, INVENTORYING, READY_FOR_ANALYSIS, FAILED
-- La constraint anterior usaba: PENDING, RUNNING, DONE, FAILED (nombres distintos)

ALTER TABLE repositories
    DROP CONSTRAINT repositories_inventory_status_check;

ALTER TABLE repositories
    ADD CONSTRAINT repositories_inventory_status_check
        CHECK (inventory_status IN ('PENDING','INVENTORYING','READY_FOR_ANALYSIS','FAILED'));
