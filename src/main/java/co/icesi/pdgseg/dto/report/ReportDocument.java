package co.icesi.pdgseg.dto.report;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * What a {@link co.icesi.pdgseg.export.ReportExporter} receives: the verified
 * report content plus the report-level metadata that lives outside it.
 */
public record ReportDocument(
        UUID reportId,
        String status,
        String checksum,
        OffsetDateTime generatedAt,
        ReportContent content
) {
}
