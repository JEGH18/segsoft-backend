package co.icesi.pdgseg.dto.response;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

public record AnalysisResultsResponse(
        AnalysisResponse analysis,
        List<FindingResponse> findings,
        List<PolicyResultResponse> policyResults,
        List<RuleExecutionErrorResponse> ruleExecutionErrors,
        BigDecimal compliancePercentage,
        Map<String, BigDecimal> categoryBreakdown
) {
}
