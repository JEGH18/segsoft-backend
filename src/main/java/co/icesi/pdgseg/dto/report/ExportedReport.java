package co.icesi.pdgseg.dto.report;

import org.springframework.http.MediaType;

/**
 * @param cacheHit whether the file was served from the export cache (X-Cache: HIT)
 *                 or generated for this request (X-Cache: MISS)
 */
public record ExportedReport(
        byte[] content,
        MediaType mediaType,
        String fileName,
        boolean cacheHit
) {
}
