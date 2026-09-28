package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.PolicySetStatus;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * GET /api/v1/policy-sets/{id}. Superset of PolicySetResponse (list item):
 * keeps policyIds/policyNames so the existing edit form on the detail page
 * doesn't need to change, and adds what "Listar y consultar el catálogo de
 * Policy Sets" (escenario 2) actually asks for -- full policy objects,
 * category coverage, and how many repositories currently use this set.
 */
public record PolicySetDetailResponse(
    UUID id,
    String name,
    String description,
    PolicySetStatus status,
    Integer version,
    List<UUID> policyIds,
    List<String> policyNames,
    List<PolicySetPolicySummary> policies,
    Map<Category, Long> categoryCoverage,
    int usageCount,
    OffsetDateTime createdAt,
    UUID createdById,
    OffsetDateTime updatedAt
) {}
