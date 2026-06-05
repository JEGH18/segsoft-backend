package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;

import java.util.UUID;

public record PolicyListItemResponse(
        UUID id,
        String name,
        String description,
        Category category,
        Framework framework,
        String controlId,
        PolicyStatus status
) {
}
