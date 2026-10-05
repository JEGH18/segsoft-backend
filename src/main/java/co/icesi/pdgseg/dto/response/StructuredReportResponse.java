package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.dto.report.ReportContent.ControlEntry;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.PolicyEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Recommendation;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * GET /api/v1/reports/{id}: the structured compliance report. Projection of
 * the frozen, checksum-verified content; the executive view (?view=executive)
 * leaves out policyResults, the individual findings (and so every evidence
 * snippet) and the framework controls, keeping metrics and recommendations.
 * Contract: src/main/resources/report/structured-report.schema.json.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record StructuredReportResponse(
        UUID id,
        ReportStatus status,
        String view,
        int schemaVersion,
        String checksum,
        boolean integrityVerified,
        List<String> exportFormats,
        Metadata metadata,
        ExecutiveSummary executiveSummary,
        List<PolicyEntry> policyResults,
        Map<String, SeverityGroup> findingsBySeverity,
        List<CategoryCoverage> claudeCodeSecurityCoverage,
        List<FrameworkCoverage> frameworkCoverage,
        TraceabilityReference traceabilityReference
) {

    public record Metadata(
            UUID reportId,
            UUID analysisId,
            UUID repositoryId,
            String repoName,
            String sourceType,
            String branch,
            OffsetDateTime generatedAt,
            String generatedBy,
            OffsetDateTime analysisStartedAt,
            OffsetDateTime analysisCompletedAt,
            int rulesExecuted,
            int rulesTotal
    ) {
    }

    public record ExecutiveSummary(
            BigDecimal compliancePercentage,
            BigDecimal weightedCompliancePercentage,
            int totalPolicies,
            int compliantPolicies,
            int nonCompliantPolicies,
            int requiresReviewPolicies,
            int totalFindings,
            int highOrCriticalFindings,
            /* Most severe level with at least one finding; null when there are none. */
            String highestSeverity,
            int ruleExecutionErrors,
            List<Recommendation> recommendations
    ) {
    }

    /** findings is omitted in the executive view. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SeverityGroup(
            int count,
            List<FindingEntry> findings
    ) {
    }

    /** compliancePercentage is null when the category had no evaluated policies (no coverage). */
    public record CategoryCoverage(
            String category,
            int policiesEvaluated,
            int compliantPolicies,
            int nonCompliantPolicies,
            int requiresReviewPolicies,
            int findings,
            int highOrCriticalFindings,
            BigDecimal compliancePercentage
    ) {
    }

    /** controls is omitted in the executive view. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FrameworkCoverage(
            String framework,
            int policiesEvaluated,
            int compliantPolicies,
            int nonCompliantPolicies,
            int requiresReviewPolicies,
            int findings,
            int highOrCriticalFindings,
            BigDecimal compliancePercentage,
            List<ControlEntry> controls
    ) {
    }

    /** API links for drill-down from the report to its sources. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record TraceabilityReference(
            String self,
            String executiveView,
            String technicalView,
            String repositoryHistory,
            String analysis,
            String analysisResults,
            String analysisFindings,
            String findingDetailTemplate,
            Map<String, String> exports,
            List<PolicyLink> policies
    ) {
    }

    public record PolicyLink(
            UUID policyId,
            String policyName,
            String policy,
            String traceability
    ) {
    }
}
