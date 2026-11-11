package co.icesi.pdgseg.dto.engine;

import java.util.List;
import java.util.Map;

/** One rule over many files of the same repository: POST /internal/execute-rule-batch. */
public record ExecuteRuleBatchRequest(
        String ruleId,
        String type,
        Map<String, Object> payload,
        List<String> artifactPaths,
        String category,
        String severity,
        String cweId
) {
}
