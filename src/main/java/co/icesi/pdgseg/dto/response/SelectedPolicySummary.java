package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;

import java.util.UUID;

public record SelectedPolicySummary(
        UUID id,
        String name,
        Framework framework,
        String controlId,
        Category category,
        long rulesCount
) {
}
