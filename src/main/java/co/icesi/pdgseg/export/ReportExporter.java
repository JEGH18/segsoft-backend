package co.icesi.pdgseg.export;

import co.icesi.pdgseg.dto.report.ReportDocument;
import org.springframework.http.MediaType;

/**
 * Strategy for rendering a verified report into one output format. Every
 * implementation registered as a Spring bean is picked up by
 * {@link ReportExporterRegistry}, so adding a format (e.g. SARIF) only means
 * adding a new exporter -- the export endpoint does not change.
 */
public interface ReportExporter {

    /** Lower-case format key, as used in {@code ?format=}. */
    String format();

    MediaType mediaType();

    /** File extension without the leading dot. */
    String fileExtension();

    byte[] export(ReportDocument report);
}
