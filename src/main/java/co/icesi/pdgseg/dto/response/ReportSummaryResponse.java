package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.ReportStatus;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * What the report view shows. Content-derived fields are null when the stored
 * content cannot be read; integrityVerified tells whether the stored checksum
 * still matches the content (exports are refused with 409 when it does not).
 */
public record ReportSummaryResponse(
        UUID id,
        UUID analysisId,
        ReportStatus status,
        String checksum,
        OffsetDateTime generatedAt,
        String generatedBy,
        String repositoryName,
        BigDecimal compliancePercentage,
        BigDecimal weightedCompliancePercentage,
        Integer policiesEvaluated,
        Integer totalFindings,
        Map<String, Integer> findingsBySeverity,
        boolean integrityVerified,
        List<String> exportFormats
) {
}
