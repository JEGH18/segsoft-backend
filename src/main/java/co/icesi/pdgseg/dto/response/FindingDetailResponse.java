package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.RuleType;
import co.icesi.pdgseg.entity.enums.SeverityLevel;

import java.util.UUID;

public record FindingDetailResponse(
        UUID id,
        UUID analysisId,
        UUID policyId,
        String policyName,
        String framework,
        String controlId,
        String category,
        RuleType ruleType,
        String filePath,
        Integer lineNumber,
        String evidenceSnippet,
        String cweId,
        SeverityLevel severity,
        String suggestedAction
) {
}
