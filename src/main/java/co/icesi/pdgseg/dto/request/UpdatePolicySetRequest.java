package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

/**
 * Every field is optional (PATCH semantics): only non-null fields are
 * changed. A non-null policyIds REPLACES the full composition -- the
 * service diffs it against the current set to compute added/removed for
 * the audit log, it isn't merged incrementally.
 */
public record UpdatePolicySetRequest(
    @Size(max = 200, message = "El nombre no puede superar 200 caracteres")
    String name,

    @Size(max = 1000, message = "La descripción no puede superar 1000 caracteres")
    String description,

    List<UUID> policyIds
) {}
