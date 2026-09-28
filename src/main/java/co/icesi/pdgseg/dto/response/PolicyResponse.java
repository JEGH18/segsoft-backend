package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public record PolicyResponse(
    UUID id,
    String name,
    String description,
    Category category,
    Framework framework,
    String controlId,
    String implementationGuideId,
    // Escenario 4: true solo para políticas ISO_27001 sin implementationGuideId
    // -- computado, no una columna propia, así que nunca puede desincronizarse.
    boolean detailPending,
    PolicyStatus status,
    Integer version,
    Integer weight,
    Map<String, Object> applicability,
    OffsetDateTime createdAt,
    UUID createdById,
    boolean executable,
    int rulesCount
) {}
