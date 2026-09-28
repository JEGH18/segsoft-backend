package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.AnalysisStatus;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.UUID;

public record AnalysisResponse(
        UUID id,
        UUID repositoryId,
        AnalysisStatus status,
        Integer rulesExecuted,
        Integer rulesTotal,
        BigDecimal progress,
        OffsetDateTime createdAt,
        OffsetDateTime startedAt,
        OffsetDateTime completedAt,
        OffsetDateTime cancelledAt,
        String errorMessage
) {
}
