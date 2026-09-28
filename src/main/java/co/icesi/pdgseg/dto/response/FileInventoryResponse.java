package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.InventoryStatus;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public record FileInventoryResponse(
        UUID repositoryId,
        InventoryStatus inventoryStatus,
        long totalFiles,
        long excludedCount,
        Map<String, Long> byLanguage,
        Map<String, Long> byArtifactType,
        int page,
        int size,
        long totalElements,
        int totalPages,
        List<RepositoryFileResponse> files
) {}
