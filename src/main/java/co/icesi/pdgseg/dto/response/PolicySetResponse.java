package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.PolicySetStatus;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record PolicySetResponse(
    UUID id,
    String name,
    String description,
    PolicySetStatus status,
    Integer version,
    List<UUID> policyIds,
    List<String> policyNames,
    OffsetDateTime createdAt,
    UUID createdById,
    OffsetDateTime updatedAt
) {}
