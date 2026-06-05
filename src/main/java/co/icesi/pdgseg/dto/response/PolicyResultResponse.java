package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;

import java.util.UUID;

public record PolicyResultResponse(
        UUID policyId,
        PolicyComplianceStatus status,
        Integer findingsCount,
        Integer highOrCriticalCount,
        Integer lowOrMediumCount
) {
}
