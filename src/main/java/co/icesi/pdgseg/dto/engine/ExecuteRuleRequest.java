package co.icesi.pdgseg.dto.engine;

import java.util.Map;

public record ExecuteRuleRequest(
        String ruleId,
        String type,
        Map<String, Object> payload,
        String artifactPath
) {
}
