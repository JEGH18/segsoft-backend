package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.Category;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public record PolicySelectionResponse(
        UUID id,
        UUID repositoryId,
        List<SelectedPolicySummary> selectedPolicies,
        Map<Category, Long> categoryCoverage,
        List<Category> uncoveredCategories,
        Integer version
) {
}
