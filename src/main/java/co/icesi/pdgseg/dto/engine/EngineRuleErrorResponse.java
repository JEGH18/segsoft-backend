package co.icesi.pdgseg.dto.engine;

/**
 * filePath is the artifact path the error belongs to, as it was sent to the engine. The batch
 * endpoint always sets it; it is null for errors that do not belong to a single file.
 */
public record EngineRuleErrorResponse(
        String errorCode,
        String message,
        String filePath
) {
    public EngineRuleErrorResponse(String errorCode, String message) {
        this(errorCode, message, null);
    }
}
