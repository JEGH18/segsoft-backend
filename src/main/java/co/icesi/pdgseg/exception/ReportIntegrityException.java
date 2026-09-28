package co.icesi.pdgseg.exception;

/** The stored checksum of a report no longer matches its content (HTTP 409). */
public class ReportIntegrityException extends RuntimeException {
    public ReportIntegrityException(String message) {
        super(message);
    }
}
