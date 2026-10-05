package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.CategoryCoverage;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Metadata;
import co.icesi.pdgseg.dto.report.ReportContent.PolicyEntry;
import co.icesi.pdgseg.dto.report.ReportContent.RuleEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Summary;
import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.dto.response.AnalysisResultsResponse;
import co.icesi.pdgseg.dto.response.FindingResponse;
import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.dto.snapshot.PolicySnapshotDto;
import co.icesi.pdgseg.dto.snapshot.RuleSnapshotDto;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicyResult;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.Rule;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.exception.ReportIntegrityException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.export.ReportExporter;
import co.icesi.pdgseg.export.ReportExporterRegistry;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.PolicyResultRepository;
import co.icesi.pdgseg.repository.ReportRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class ReportService {

    private final ReportRepository reportRepository;
    private final AnalysisRepository analysisRepository;
    private final PolicyResultRepository policyResultRepository;
    private final RuleRepository ruleRepository;
    private final UserRepository userRepository;
    private final AnalysisService analysisService;
    private final AnalysisSnapshotService analysisSnapshotService;
    private final SecretMaskingService secretMaskingService;
    private final ReportExporterRegistry exporterRegistry;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public ReportService(
            ReportRepository reportRepository,
            AnalysisRepository analysisRepository,
            PolicyResultRepository policyResultRepository,
            RuleRepository ruleRepository,
            UserRepository userRepository,
            AnalysisService analysisService,
            AnalysisSnapshotService analysisSnapshotService,
            SecretMaskingService secretMaskingService,
            ReportExporterRegistry exporterRegistry,
            AuditService auditService,
            ObjectMapper objectMapper
    ) {
        this.reportRepository = reportRepository;
        this.analysisRepository = analysisRepository;
        this.policyResultRepository = policyResultRepository;
        this.ruleRepository = ruleRepository;
        this.userRepository = userRepository;
        this.analysisService = analysisService;
        this.analysisSnapshotService = analysisSnapshotService;
        this.secretMaskingService = secretMaskingService;
        this.exporterRegistry = exporterRegistry;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    /**
     * Freezes the results of a COMPLETED analysis into a new report. The
     * content is serialized once and its SHA-256 stored alongside it; exports
     * always render from that stored JSON, never from the live tables.
     */
    @Transactional
    public ReportResponse generate(UUID analysisId, String username) {
        Analysis analysis = analysisRepository.findById(analysisId)
                .orElseThrow(() -> new ResourceNotFoundException("Análisis no encontrado"));
        if (analysis.getStatus() != AnalysisStatus.COMPLETED) {
            throw new UnprocessableEntityException(
                    "Solo se puede generar un reporte de un análisis COMPLETED (estado actual: "
                            + analysis.getStatus() + ")");
        }

        OffsetDateTime generatedAt = OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS);
        ReportContent content = buildContent(analysis, username, generatedAt);
        String contentJson = serialize(content);

        Report report = new Report();
        report.setAnalysis(analysis);
        report.setStatus(ReportStatus.GENERATED);
        report.setContentJson(contentJson);
        report.setChecksum(sha256Hex(contentJson));
        report.setGeneratedBy(userRepository.findByUsername(username).orElse(null));
        report.setGeneratedAt(generatedAt);
        report = reportRepository.save(report);

        auditService.record("REPORT_GENERATED", username, null,
                Map.of("reportId", report.getId().toString(), "analysisId", analysisId.toString()));
        return new ReportResponse(report.getId(), analysisId, report.getStatus(), report.getChecksum(),
                report.getGeneratedAt());
    }

    /**
     * Resolves the exporter first (unsupported format -> 400 without touching
     * the database), then loads and verifies the report (404 / 409) and only
     * then renders it, so a tampered report never produces a file.
     *
     * Deliberately not transactional: the integrity-violation audit entry must
     * be committed even though the call ends in an exception.
     */
    public ExportedReport export(UUID reportId, String format, String username) {
        ReportExporter exporter = exporterRegistry.resolve(format);
        ReportDocument document = loadVerified(reportId, username);
        byte[] bytes = exporter.export(document);
        auditService.record("REPORT_EXPORTED", username, null,
                Map.of("reportId", reportId.toString(), "format", exporter.format()));
        return new ExportedReport(bytes, exporter.mediaType(),
                "segsoft-report-" + reportId + "." + exporter.fileExtension());
    }

    private ReportDocument loadVerified(UUID reportId, String username) {
        Report report = reportRepository.findById(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("Reporte no encontrado"));

        byte[] expected = report.getChecksum() == null
                ? new byte[0]
                : report.getChecksum().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII);
        byte[] actual = sha256Hex(report.getContentJson()).getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, actual)) {
            auditService.record("REPORT_INTEGRITY_VIOLATION", username, null,
                    Map.of("reportId", reportId.toString()));
            throw new ReportIntegrityException(
                    "El checksum almacenado del reporte no coincide con su contenido; no se generó el archivo");
        }

        ReportContent content;
        try {
            content = objectMapper.readValue(report.getContentJson(), ReportContent.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Contenido del reporte ilegible", e);
        }
        return new ReportDocument(report.getId(), report.getStatus().name(), report.getChecksum(),
                report.getGeneratedAt(), content);
    }

    // ---- Content assembly -----------------------------------------------------

    private ReportContent buildContent(Analysis analysis, String username, OffsetDateTime generatedAt) {
        AnalysisResultsResponse results = analysisService.getResults(analysis.getId());
        List<PolicyResult> policyResults = policyResultRepository.findByAnalysisId(analysis.getId());

        List<PolicyEntry> policies = policyResults.stream().map(this::toPolicyEntry).toList();
        List<FindingEntry> findings = results.findings().stream().map(this::toFindingEntry).toList();

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (SeverityLevel level : new SeverityLevel[]{
                SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW}) {
            bySeverity.put(level.name(), (int) findings.stream().filter(f -> level.name().equals(f.severity())).count());
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
                categoryCoverage(policies, findings), policies, findings, executedRules(analysis.getId()));
    }

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

    /** getResults() already masks the snippet; it is stored masked. */
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
                finding.suggestedAction(),
                finding.fileSha256()
        );
    }

    private static List<CategoryCoverage> categoryCoverage(List<PolicyEntry> policies, List<FindingEntry> findings) {
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
                    (int) categoryFindings.stream()
                            .filter(f -> "HIGH".equals(f.severity()) || "CRITICAL".equals(f.severity()))
                            .count()
            ));
        }
        return coverage;
    }

    private static int countStatus(List<PolicyEntry> policies, PolicyComplianceStatus status) {
        return (int) policies.stream().filter(p -> status.name().equals(p.status())).count();
    }

    private String serialize(ReportContent content) {
        try {
            return objectMapper.writeValueAsString(content);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("No se pudo serializar el reporte", e);
        }
    }

    static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }
}
