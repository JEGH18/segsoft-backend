package co.icesi.pdgseg.exception;

/** The exported file exceeds MAX_EXPORT_SIZE_MB (HTTP 422). */
public class ExportTooLargeException extends RuntimeException {

    private final long sizeBytes;
    private final long maxSizeMb;

    public ExportTooLargeException(long sizeBytes, long maxSizeMb) {
        super(String.format(java.util.Locale.ROOT,
                "El archivo exportado ocupa %.1f MB y supera el tamaño máximo permitido de %d MB "
                        + "(MAX_EXPORT_SIZE_MB). Reduzca el alcance del análisis o pida al administrador ampliar el límite.",
                sizeBytes / (1024.0 * 1024.0), maxSizeMb));
        this.sizeBytes = sizeBytes;
        this.maxSizeMb = maxSizeMb;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public long getMaxSizeMb() {
        return maxSizeMb;
    }
}
