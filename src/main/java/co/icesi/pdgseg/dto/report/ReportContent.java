package co.icesi.pdgseg.dto.report;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Self-contained, format-agnostic content of a compliance report. It is
 * serialized once into reports.content_json (the checksummed bytes) and every
 * exporter renders from it, so a PDF and a future SARIF export of the same
 * report always describe exactly the same results -- even after the source
 * repository/analysis has been deleted.
 *
 * Evidence snippets are stored already masked; exporters mask them again as
 * defense in depth.
 */
public record ReportContent(
        int schemaVersion,
        Metadata metadata,
        Summary summary,
        List<CategoryCoverage> categoryCoverage,
        List<PolicyEntry> policyResults,
        List<FindingEntry> findings,
        /*
         * Rules executed by the analysis (schema v2). Null in reports frozen
         * with schema v1, whose exporters derive them from the findings.
         */
        List<RuleEntry> rules
) {

    public static final int CURRENT_SCHEMA_VERSION = 2;

    public record Metadata(
            UUID analysisId,
            UUID repositoryId,
            String repositoryName,
            String sourceType,
            String gitUrl,
            String branch,
            String repositorySha256,
            OffsetDateTime analysisStartedAt,
            OffsetDateTime analysisCompletedAt,
            int rulesExecuted,
            int rulesTotal,
            String generatedBy,
            OffsetDateTime generatedAt
    ) {
    }

    public record Summary(
            BigDecimal compliancePercentage,
            BigDecimal weightedCompliancePercentage,
            int policiesEvaluated,
            int compliantPolicies,
            int nonCompliantPolicies,
            int requiresReviewPolicies,
            int totalFindings,
            /* Keyed by SeverityLevel name, always holding all four levels. */
            Map<String, Integer> findingsBySeverity,
            int executionErrors
    ) {
    }

    /** One entry per catalog Category, present even when nothing was evaluated for it. */
    public record CategoryCoverage(
            String category,
            int policiesEvaluated,
            int compliantPolicies,
            int nonCompliantPolicies,
            int requiresReviewPolicies,
            int findings,
            int highOrCriticalFindings
    ) {
    }

    public record PolicyEntry(
            UUID policyId,
            String name,
            String category,
            String framework,
            String controlId,
            Integer weight,
            String status,
            int findingsCount,
            int highOrCriticalCount,
            int lowOrMediumCount
    ) {
    }

    public record FindingEntry(
            UUID findingId,
            UUID policyId,
            String policyName,
            UUID ruleId,
            String severity,
            String category,
            String cweId,
            String filePath,
            Integer lineNumber,
            String evidenceSnippet,
            String suggestedAction,
            String fileSha256
    ) {
    }

    public record RuleEntry(
            UUID ruleId,
            UUID policyId,
            String policyName,
            String type,
            String severity,
            String category,
            String cweId,
            String description
    ) {
    }
}
