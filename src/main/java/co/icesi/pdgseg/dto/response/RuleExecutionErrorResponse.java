package co.icesi.pdgseg.dto.response;

import java.util.UUID;

public record RuleExecutionErrorResponse(
        UUID id,
        UUID policyId,
        UUID ruleId,
        String errorCode,
        String message,
        String filePath
) {
}
