package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.PolicyEntry;
import co.icesi.pdgseg.dto.response.StructuredReportResponse;
import co.icesi.pdgseg.dto.response.StructuredReportResponse.CategoryCoverage;
import co.icesi.pdgseg.dto.response.StructuredReportResponse.ExecutiveSummary;
import co.icesi.pdgseg.dto.response.StructuredReportResponse.FrameworkCoverage;
import co.icesi.pdgseg.dto.response.StructuredReportResponse.Metadata;
import co.icesi.pdgseg.dto.response.StructuredReportResponse.PolicyLink;
import co.icesi.pdgseg.dto.response.StructuredReportResponse.SeverityGroup;
import co.icesi.pdgseg.dto.response.StructuredReportResponse.TraceabilityReference;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.entity.enums.Category;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Projects a verified, frozen report into the structured API document. It
 * only reshapes the stored content: every metric comes from it as stored.
 * Reports frozen before schema v3 lack frameworkCoverage/recommendations;
 * those are derived here from their own frozen policies and findings, with
 * the same functions the generator uses.
 */
@Component
public class StructuredReportMapper {

    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    private final SecretMaskingService secretMaskingService;

    public StructuredReportMapper(SecretMaskingService secretMaskingService) {
        this.secretMaskingService = secretMaskingService;
    }

    public StructuredReportResponse toResponse(Report report, ReportContent content, ReportView view,
                                               List<String> exportFormats) {
        boolean technical = view == ReportView.TECHNICAL;
        List<PolicyEntry> policies = nonNull(content.policyResults());
        List<FindingEntry> findings = nonNull(content.findings()).stream().map(this::remask).toList();

        return new StructuredReportResponse(
                report.getId(),
                report.getStatus(),
                view.key(),
                content.schemaVersion(),
                report.getChecksum(),
                true,
                exportFormats,
                metadata(report, content),
                executiveSummary(content, policies, findings),
                technical ? policies : null,
                findingsBySeverity(findings, technical),
                categoryCoverage(content),
                frameworkCoverage(content, policies, findings, technical),
                traceability(report, content, policies, view)
        );
    }

    private static Metadata metadata(Report report, ReportContent content) {
        ReportContent.Metadata m = content.metadata();
        return new Metadata(report.getId(), m.analysisId(), m.repositoryId(), m.repositoryName(), m.sourceType(),
                m.branch(), report.getGeneratedAt(), m.generatedBy(), m.analysisStartedAt(), m.analysisCompletedAt(),
                m.rulesExecuted(), m.rulesTotal());
    }

    private static ExecutiveSummary executiveSummary(ReportContent content, List<PolicyEntry> policies,
                                                     List<FindingEntry> findings) {
        ReportContent.Summary s = content.summary();
        Map<String, Integer> bySeverity = s.findingsBySeverity() != null ? s.findingsBySeverity() : Map.of();
        String highest = SEVERITIES.stream().filter(level -> bySeverity.getOrDefault(level, 0) > 0)
                .findFirst().orElse(null);
        return new ExecutiveSummary(
                s.compliancePercentage(),
                s.weightedCompliancePercentage(),
                s.policiesEvaluated(),
                s.compliantPolicies(),
                s.nonCompliantPolicies(),
                s.requiresReviewPolicies(),
                s.totalFindings(),
                bySeverity.getOrDefault("CRITICAL", 0) + bySeverity.getOrDefault("HIGH", 0),
                highest,
                s.executionErrors(),
                content.recommendations() != null
                        ? content.recommendations()
                        : ReportGeneratorService.recommendations(policies, findings));
    }

    private static Map<String, SeverityGroup> findingsBySeverity(List<FindingEntry> findings, boolean technical) {
        Map<String, SeverityGroup> groups = new LinkedHashMap<>();
        for (String level : SEVERITIES) {
            List<FindingEntry> inLevel = findings.stream()
                    .filter(f -> level.equals(f.severity()))
                    .sorted(Comparator.comparing((FindingEntry f) -> String.valueOf(f.filePath()))
                            .thenComparing(f -> f.lineNumber() != null ? f.lineNumber() : 0))
                    .toList();
            groups.put(level, new SeverityGroup(inLevel.size(), technical ? inLevel : null));
        }
        return groups;
    }

    /**
     * Always the five catalog categories, in catalog order: a category the
     * frozen content does not list (older reports only listed some) had no
     * evaluated policies, i.e. no coverage.
     */
    private static List<CategoryCoverage> categoryCoverage(ReportContent content) {
        Map<String, ReportContent.CategoryCoverage> frozen = new LinkedHashMap<>();
        nonNull(content.categoryCoverage()).forEach(c -> frozen.putIfAbsent(c.category(), c));
        return Arrays.stream(Category.values())
                .map(category -> frozen.getOrDefault(category.name(),
                        new ReportContent.CategoryCoverage(category.name(), 0, 0, 0, 0, 0, 0)))
                .map(c -> new CategoryCoverage(c.category(), c.policiesEvaluated(), c.compliantPolicies(),
                        c.nonCompliantPolicies(), c.requiresReviewPolicies(), c.findings(),
                        c.highOrCriticalFindings(), percentage(c.compliantPolicies(), c.policiesEvaluated())))
                .toList();
    }

    private static List<FrameworkCoverage> frameworkCoverage(ReportContent content, List<PolicyEntry> policies,
                                                             List<FindingEntry> findings, boolean technical) {
        List<ReportContent.FrameworkCoverage> frozen = content.frameworkCoverage() != null
                ? content.frameworkCoverage()
                : ReportGeneratorService.frameworkCoverage(policies, findings);
        return frozen.stream()
                .map(f -> new FrameworkCoverage(f.framework(), f.policiesEvaluated(), f.compliantPolicies(),
                        f.nonCompliantPolicies(), f.requiresReviewPolicies(), f.findings(),
                        f.highOrCriticalFindings(), percentage(f.compliantPolicies(), f.policiesEvaluated()),
                        technical ? f.controls() : null))
                .toList();
    }

    private static TraceabilityReference traceability(Report report, ReportContent content,
                                                      List<PolicyEntry> policies, ReportView view) {
        String self = "/api/v1/reports/" + report.getId();
        UUID analysisId = content.metadata().analysisId();
        UUID repositoryId = content.metadata().repositoryId();
        Map<String, String> exports = new LinkedHashMap<>();
        exports.put("pdf", self + "/export?format=pdf");
        exports.put("sarif", self + "/export?format=sarif");
        List<PolicyLink> policyLinks = policies.stream()
                .filter(p -> p.policyId() != null)
                .map(p -> new PolicyLink(p.policyId(), p.name(), "/api/v1/policies/" + p.policyId(),
                        "/api/v1/policies/" + p.policyId() + "/traceability"))
                .toList();
        return new TraceabilityReference(
                view == ReportView.EXECUTIVE ? self + "?view=executive" : self,
                self + "?view=executive",
                self + "?view=technical",
                repositoryId != null ? "/api/v1/reports?repositoryId=" + repositoryId : null,
                analysisId != null ? "/api/v1/analyses/" + analysisId : null,
                analysisId != null ? "/api/v1/analyses/" + analysisId + "/results" : null,
                analysisId != null ? "/api/v1/analyses/" + analysisId + "/findings" : null,
                "/api/v1/findings/{findingId}",
                exports,
                policyLinks);
    }

    /** Snippets were masked when frozen; masking again on the way out is cheap defense in depth. */
    private FindingEntry remask(FindingEntry f) {
        return new FindingEntry(f.findingId(), f.policyId(), f.policyName(), f.ruleId(), f.severity(), f.category(),
                f.cweId(), f.filePath(), f.lineNumber(), secretMaskingService.mask(f.evidenceSnippet()),
                secretMaskingService.mask(f.suggestedAction()), f.fileSha256());
    }

    private static BigDecimal percentage(int part, int total) {
        if (total == 0) {
            return null;
        }
        return BigDecimal.valueOf(part).multiply(BigDecimal.valueOf(100))
                .divide(BigDecimal.valueOf(total), 2, RoundingMode.HALF_UP);
    }

    private static <T> List<T> nonNull(List<T> list) {
        return list != null ? list.stream().filter(Objects::nonNull).toList() : List.of();
    }
}
