package co.icesi.pdgseg.dto.report;

import org.springframework.http.MediaType;

public record ExportedReport(
        byte[] content,
        MediaType mediaType,
        String fileName
) {
}
