package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.CategoryCoverage;
import co.icesi.pdgseg.dto.report.ReportContent.ControlEntry;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.FrameworkCoverage;
import co.icesi.pdgseg.dto.report.ReportContent.Metadata;
import co.icesi.pdgseg.dto.report.ReportContent.PolicyEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Recommendation;
import co.icesi.pdgseg.dto.report.ReportContent.RuleEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Summary;
import co.icesi.pdgseg.dto.response.AnalysisResultsResponse;
import co.icesi.pdgseg.dto.response.FindingResponse;
import co.icesi.pdgseg.dto.snapshot.PolicySnapshotDto;
import co.icesi.pdgseg.dto.snapshot.RuleSnapshotDto;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicyResult;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.Rule;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.repository.PolicyResultRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Consolidates a COMPLETED analysis into the frozen content of a compliance
 * report: metadata, executive summary, per-policy results, findings,
 * coverage of the five Claude Code Security catalog categories, coverage per
 * regulatory framework, prioritized recommendations and the rules executed.
 *
 * Everything is read from the analysis at generation time and copied into
 * the content, which is then stored append-only; later changes to the
 * repository, the policies or the rules never reach an existing report.
 */
@Service
public class ReportGeneratorService {

    static final int MAX_RECOMMENDATIONS = 10;
    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");
    private static final List<String> STATUS_ORDER = List.of("NON_COMPLIANT", "REQUIRES_REVIEW", "COMPLIANT");

    private final AnalysisService analysisService;
    private final PolicyResultRepository policyResultRepository;
    private final RuleRepository ruleRepository;
    private final AnalysisSnapshotService analysisSnapshotService;
    private final SecretMaskingService secretMaskingService;

    public ReportGeneratorService(
            AnalysisService analysisService,
            PolicyResultRepository policyResultRepository,
            RuleRepository ruleRepository,
            AnalysisSnapshotService analysisSnapshotService,
            SecretMaskingService secretMaskingService
    ) {
        this.analysisService = analysisService;
        this.policyResultRepository = policyResultRepository;
        this.ruleRepository = ruleRepository;
        this.analysisSnapshotService = analysisSnapshotService;
        this.secretMaskingService = secretMaskingService;
    }

    @Transactional(readOnly = true)
    public ReportContent generate(Analysis analysis, String username, OffsetDateTime generatedAt) {
        AnalysisResultsResponse results = analysisService.getResults(analysis.getId());
        List<PolicyResult> policyResults = policyResultRepository.findByAnalysisId(analysis.getId());

        List<PolicyEntry> policies = policyResults.stream().map(this::toPolicyEntry).toList();
        List<FindingEntry> findings = results.findings().stream().map(this::toFindingEntry).toList();

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (String level : SEVERITY_ORDER) {
            bySeverity.put(level, (int) findings.stream().filter(f -> level.equals(f.severity())).count());
        }

        Summary summary = new Summary(
                results.compliancePercentage(),
                results.weightedCompliancePercentage(),
                policies.size(),
                countStatus(policies, PolicyComplianceStatus.COMPLIANT),
                countStatus(policies, PolicyComplianceStatus.NON_COMPLIANT),
                countStatus(policies, PolicyComplianceStatus.REQUIRES_REVIEW),
                findings.size(),
                bySeverity,
                results.ruleExecutionErrors().size()
        );

        Repository repository = analysis.getRepository();
        Metadata metadata = new Metadata(
                analysis.getId(),
                repository.getId(),
                repository.getOriginalName(),
                repository.getSourceType() != null ? repository.getSourceType().name() : null,
                secretMaskingService.mask(repository.getGitUrl()),
                repository.getBranch(),
                repository.getSha256Archive(),
                analysis.getStartedAt(),
                analysis.getCompletedAt(),
                analysis.getRulesExecuted() != null ? analysis.getRulesExecuted() : 0,
                analysis.getRulesTotal() != null ? analysis.getRulesTotal() : 0,
                username,
                generatedAt
        );

        return new ReportContent(ReportContent.CURRENT_SCHEMA_VERSION, metadata, summary,
                categoryCoverage(policies, findings), policies, findings, executedRules(analysis.getId()),
                frameworkCoverage(policies, findings), recommendations(policies, findings));
    }

    // ---- Claude Code Security catalog ------------------------------------------------

    /** One entry per catalog category, present even when nothing was evaluated for it. */
    static List<CategoryCoverage> categoryCoverage(List<PolicyEntry> policies, List<FindingEntry> findings) {
        List<CategoryCoverage> coverage = new ArrayList<>();
        for (Category category : Category.values()) {
            String name = category.name();
            List<PolicyEntry> inCategory = policies.stream().filter(p -> name.equals(p.category())).toList();
            List<FindingEntry> categoryFindings = findings.stream().filter(f -> name.equals(f.category())).toList();
            coverage.add(new CategoryCoverage(
                    name,
                    inCategory.size(),
                    countStatus(inCategory, PolicyComplianceStatus.COMPLIANT),
                    countStatus(inCategory, PolicyComplianceStatus.NON_COMPLIANT),
                    countStatus(inCategory, PolicyComplianceStatus.REQUIRES_REVIEW),
                    categoryFindings.size(),
                    highOrCritical(categoryFindings)
            ));
        }
        return coverage;
    }

    // ---- Regulatory frameworks ------------------------------------------------------

    /**
     * Evaluated policies grouped by the framework they trace to, in catalog
     * order, with the framework controls they implement. A control
     * implemented by several policies takes the worst of their statuses.
     */
    public static List<FrameworkCoverage> frameworkCoverage(List<PolicyEntry> policies, List<FindingEntry> findings) {
        List<String> frameworkOrder = Arrays.stream(Framework.values()).map(Enum::name).toList();
        Map<String, List<PolicyEntry>> byFramework = policies.stream()
                .collect(Collectors.groupingBy(p -> p.framework() != null ? p.framework() : "UNSPECIFIED",
                        LinkedHashMap::new, Collectors.toList()));

        List<FrameworkCoverage> coverage = new ArrayList<>();
        byFramework.entrySet().stream()
                .sorted(Comparator.comparingInt(e -> rank(frameworkOrder, e.getKey())))
                .forEach(entry -> {
                    List<PolicyEntry> inFramework = entry.getValue();
                    List<UUID> policyIds = inFramework.stream().map(PolicyEntry::policyId).toList();
                    List<FindingEntry> frameworkFindings = findings.stream()
                            .filter(f -> f.policyId() != null && policyIds.contains(f.policyId()))
                            .toList();
                    coverage.add(new FrameworkCoverage(
                            entry.getKey(),
                            inFramework.size(),
                            countStatus(inFramework, PolicyComplianceStatus.COMPLIANT),
                            countStatus(inFramework, PolicyComplianceStatus.NON_COMPLIANT),
                            countStatus(inFramework, PolicyComplianceStatus.REQUIRES_REVIEW),
                            frameworkFindings.size(),
                            highOrCritical(frameworkFindings),
                            controls(inFramework)));
                });
        return coverage;
    }

    private static List<ControlEntry> controls(List<PolicyEntry> policies) {
        Map<String, List<PolicyEntry>> byControl = new TreeMap<>();
        for (PolicyEntry policy : policies) {
            if (policy.controlId() != null && !policy.controlId().isBlank()) {
                byControl.computeIfAbsent(policy.controlId().trim(), k -> new ArrayList<>()).add(policy);
            }
        }
        List<ControlEntry> controls = new ArrayList<>();
        byControl.forEach((controlId, implementing) -> controls.add(new ControlEntry(
                controlId,
                implementing.stream().map(PolicyEntry::status)
                        .min(Comparator.comparingInt(s -> rank(STATUS_ORDER, s))).orElse(null),
                implementing.stream().map(PolicyEntry::policyId).sorted().toList())));
        return controls;
    }

    // ---- Recommendations ---------------------------------------------------------------

    /**
     * One recommendation per policy that is not compliant, most urgent first:
     * highest finding severity, then number of high/critical findings, then
     * policy weight. The action is the suggestion the findings repeat most
     * often (already masked), or a generic one when they carry none.
     */
    public static List<Recommendation> recommendations(List<PolicyEntry> policies, List<FindingEntry> findings) {
        record Candidate(PolicyEntry policy, List<FindingEntry> findings, String highestSeverity) {
        }
        List<Candidate> candidates = policies.stream()
                .filter(p -> !PolicyComplianceStatus.COMPLIANT.name().equals(p.status()))
                .map(policy -> {
                    List<FindingEntry> own = findings.stream()
                            .filter(f -> Objects.equals(f.policyId(), policy.policyId()))
                            .toList();
                    String highest = own.stream().map(FindingEntry::severity)
                            .min(Comparator.comparingInt(s -> rank(SEVERITY_ORDER, s))).orElse(null);
                    return new Candidate(policy, own, highest);
                })
                .sorted(Comparator.comparingInt((Candidate c) -> rank(SEVERITY_ORDER, c.highestSeverity()))
                        .thenComparing(c -> -highOrCritical(c.findings()))
                        .thenComparing(c -> -(c.policy().weight() != null ? c.policy().weight() : 0))
                        .thenComparing(c -> String.valueOf(c.policy().name())))
                .limit(MAX_RECOMMENDATIONS)
                .toList();

        List<Recommendation> recommendations = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) {
            Candidate c = candidates.get(i);
            recommendations.add(new Recommendation(
                    i + 1,
                    c.policy().policyId(),
                    c.policy().name(),
                    c.policy().category(),
                    c.policy().status(),
                    c.highestSeverity(),
                    c.findings().size(),
                    highOrCritical(c.findings()),
                    action(c.policy(), c.findings())));
        }
        return recommendations;
    }

    private static String action(PolicyEntry policy, List<FindingEntry> findings) {
        return findings.stream()
                .map(FindingEntry::suggestedAction)
                .filter(a -> a != null && !a.isBlank())
                .collect(Collectors.groupingBy(String::trim, TreeMap::new, Collectors.counting()))
                .entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElseGet(() -> PolicyComplianceStatus.REQUIRES_REVIEW.name().equals(policy.status())
                        ? "Revisar manualmente la evidencia de la política «" + policy.name() + "» para confirmar su cumplimiento."
                        : "Corregir los hallazgos que incumplen la política «" + policy.name() + "».");
    }

    // ---- Executed rules ---------------------------------------------------------------

    /**
     * The rules the analysis actually ran, taken from its snapshot (the
     * policy/rule set frozen when it started) rather than from the live
     * catalog, which may have changed since. CWE ids are not part of the
     * snapshot, so they are looked up on the rule rows.
     */
    private List<RuleEntry> executedRules(UUID analysisId) {
        List<PolicySnapshotDto> policies = analysisSnapshotService.findSnapshot(analysisId)
                .map(snapshot -> snapshot.policies() != null ? snapshot.policies() : List.<PolicySnapshotDto>of())
                .orElse(List.of());
        List<UUID> ruleIds = policies.stream()
                .flatMap(policy -> policy.rules().stream())
                .map(RuleSnapshotDto::ruleId)
                .toList();
        Map<UUID, Rule> rulesById = ruleRepository.findAllById(ruleIds).stream()
                .collect(Collectors.toMap(Rule::getId, Function.identity()));

        List<RuleEntry> rules = new ArrayList<>();
        for (PolicySnapshotDto policy : policies) {
            for (RuleSnapshotDto rule : policy.rules()) {
                Rule entity = rulesById.get(rule.ruleId());
                Object description = rule.payload() != null ? rule.payload().get("description") : null;
                rules.add(new RuleEntry(
                        rule.ruleId(),
                        policy.policyId(),
                        policy.name(),
                        rule.type(),
                        rule.severity(),
                        rule.category() != null ? rule.category() : policy.category(),
                        entity != null ? entity.getCweId() : null,
                        description instanceof String text ? secretMaskingService.mask(text) : null
                ));
            }
        }
        rules.sort(Comparator.comparing((RuleEntry r) -> String.valueOf(r.category()))
                .thenComparing(r -> String.valueOf(r.policyName()))
                .thenComparing(r -> r.ruleId().toString()));
        return rules;
    }

    // ---- Mapping ------------------------------------------------------------------------

    private PolicyEntry toPolicyEntry(PolicyResult result) {
        Policy policy = result.getPolicy();
        return new PolicyEntry(
                policy.getId(),
                policy.getName(),
                policy.getCategory() != null ? policy.getCategory().name() : null,
                policy.getFramework() != null ? policy.getFramework().name() : null,
                policy.getControlId(),
                policy.getWeight(),
                result.getStatus().name(),
                result.getFindingsCount() != null ? result.getFindingsCount() : 0,
                result.getHighOrCriticalCount() != null ? result.getHighOrCriticalCount() : 0,
                result.getLowOrMediumCount() != null ? result.getLowOrMediumCount() : 0
        );
    }

    /** getResults() already masks the snippet; it is masked again and stored masked. */
    private FindingEntry toFindingEntry(FindingResponse finding) {
        return new FindingEntry(
                finding.id(),
                finding.policyId(),
                finding.policyName(),
                finding.ruleId(),
                finding.severity() != null ? finding.severity().name() : null,
                finding.category(),
                finding.cweId(),
                finding.filePath(),
                finding.lineNumber(),
                secretMaskingService.mask(finding.evidenceSnippet()),
                secretMaskingService.mask(finding.suggestedAction()),
                finding.fileSha256()
        );
    }

    // ---- helpers -------------------------------------------------------------------------

    private static int countStatus(List<PolicyEntry> policies, PolicyComplianceStatus status) {
        return (int) policies.stream().filter(p -> status.name().equals(p.status())).count();
    }

    private static int highOrCritical(List<FindingEntry> findings) {
        return (int) findings.stream()
                .filter(f -> SeverityLevel.HIGH.name().equals(f.severity()) || SeverityLevel.CRITICAL.name().equals(f.severity()))
                .count();
    }

    private static int rank(List<String> order, String value) {
        int index = value == null ? -1 : order.indexOf(value);
        return index < 0 ? order.size() : index;
    }
}
