package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.ReportStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ReportResponse(
        UUID id,
        UUID analysisId,
        ReportStatus status,
        String checksum,
        OffsetDateTime generatedAt
) {
}
