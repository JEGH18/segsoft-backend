package co.icesi.pdgseg.export.cache;

import co.icesi.pdgseg.exception.ExportTooLargeException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Maximum size of a file sent to the client, set with MAX_EXPORT_SIZE_MB (default 50). */
@Component
public class ExportSizeLimit {

    private static final long BYTES_PER_MB = 1024L * 1024L;

    private final long maxSizeMb;

    public ExportSizeLimit(@Value("${report.export.max-size-mb}") long maxSizeMb) {
        if (maxSizeMb <= 0) {
            throw new IllegalArgumentException("MAX_EXPORT_SIZE_MB debe ser positivo: " + maxSizeMb);
        }
        this.maxSizeMb = maxSizeMb;
    }

    public long maxSizeMb() {
        return maxSizeMb;
    }

    /** @throws ExportTooLargeException when {@code sizeBytes} is above the limit. */
    public void check(long sizeBytes) {
        if (sizeBytes > maxSizeMb * BYTES_PER_MB) {
            throw new ExportTooLargeException(sizeBytes, maxSizeMb);
        }
    }
}
