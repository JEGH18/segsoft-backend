package co.icesi.pdgseg.dto.engine;

public record EngineRuleErrorResponse(
        String errorCode,
        String message
) {
}
