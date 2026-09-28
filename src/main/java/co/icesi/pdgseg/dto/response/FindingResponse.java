package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.SeverityLevel;

import java.util.UUID;

public record FindingResponse(
        UUID id,
        UUID policyId,
        String policyName,
        UUID ruleId,
        SeverityLevel severity,
        String category,
        String filePath,
        Integer lineNumber,
        String evidenceSnippet,
        String fileSha256,
        String cweId,
        String suggestedAction
) {
}
