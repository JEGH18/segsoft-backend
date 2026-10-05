package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.ReportStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

/** Answer of POST /api/v1/analyses/{id}/reports; url is also sent as the Location header. */
public record ReportResponse(
        UUID id,
        UUID analysisId,
        ReportStatus status,
        String checksum,
        OffsetDateTime generatedAt,
        String url
) {
    public ReportResponse(UUID id, UUID analysisId, ReportStatus status, String checksum, OffsetDateTime generatedAt) {
        this(id, analysisId, status, checksum, generatedAt, "/api/v1/reports/" + id);
    }
}
