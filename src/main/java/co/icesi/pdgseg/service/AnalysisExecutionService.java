package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.engine.EngineFindingResponse;
import co.icesi.pdgseg.dto.engine.EngineRuleErrorResponse;
import co.icesi.pdgseg.dto.engine.ExecuteRuleBatchRequest;
import co.icesi.pdgseg.dto.engine.ExecuteRuleResponse;
import co.icesi.pdgseg.dto.snapshot.AnalysisSnapshotDto;
import co.icesi.pdgseg.dto.snapshot.PolicySnapshotDto;
import co.icesi.pdgseg.dto.snapshot.RuleSnapshotDto;
import co.icesi.pdgseg.entity.*;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.observability.AnalysisMetrics;
import co.icesi.pdgseg.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.*;

/**
 * Runs an analysis: every rule of the snapshot over every inventoried file, through the engine.
 *
 * <p>Transactions: the run is deliberately NOT one transaction. Each save is its own short
 * transaction (Spring Data's default), so the progress, the findings and a cancellation are
 * visible to other requests while the analysis runs. Only the policy results, which are
 * deleted and written again as a whole, use an explicit transaction. (The methods used to carry
 * {@code @Transactional}, but they are called from inside this class, which bypasses Spring's
 * proxy: the annotations never had any effect.)
 *
 * <p>Each rule is sent to the engine in batches of {@code engine.batch-size} files, one HTTP
 * request per batch instead of one per file.
 */
@Service
public class AnalysisExecutionService {

    private static final Logger log = LoggerFactory.getLogger(AnalysisExecutionService.class);
    private static final List<SeverityLevel> HIGH_OR_CRITICAL = List.of(SeverityLevel.HIGH, SeverityLevel.CRITICAL);
    private static final List<SeverityLevel> LOW_OR_MEDIUM = List.of(SeverityLevel.LOW, SeverityLevel.MEDIUM);

    private final AnalysisRepository analysisRepository;
    private final RepositoryFileRepository repositoryFileRepository;
    private final RepositoryJpaRepository repositoryJpaRepository;
    private final FindingRepository findingRepository;
    private final PolicyResultRepository policyResultRepository;
    private final RuleExecutionErrorRepository ruleExecutionErrorRepository;
    private final PolicyRepository policyRepository;
    private final RuleRepository ruleRepository;
    private final AnalysisSnapshotService analysisSnapshotService;
    private final EngineClient engineClient;
    private final SecretMaskingService secretMaskingService;
    private final AnalysisMetrics metrics;
    private final TransactionTemplate transactionTemplate;
    private final int batchSize;

    public AnalysisExecutionService(
            AnalysisRepository analysisRepository,
            RepositoryFileRepository repositoryFileRepository,
            RepositoryJpaRepository repositoryJpaRepository,
            FindingRepository findingRepository,
            PolicyResultRepository policyResultRepository,
            RuleExecutionErrorRepository ruleExecutionErrorRepository,
            PolicyRepository policyRepository,
            RuleRepository ruleRepository,
            AnalysisSnapshotService analysisSnapshotService,
            EngineClient engineClient,
            SecretMaskingService secretMaskingService,
            AnalysisMetrics metrics,
            PlatformTransactionManager transactionManager,
            @Value("${engine.batch-size:100}") int batchSize
    ) {
        this.analysisRepository = analysisRepository;
        this.repositoryFileRepository = repositoryFileRepository;
        this.repositoryJpaRepository = repositoryJpaRepository;
        this.findingRepository = findingRepository;
        this.policyResultRepository = policyResultRepository;
        this.ruleExecutionErrorRepository = ruleExecutionErrorRepository;
        this.policyRepository = policyRepository;
        this.ruleRepository = ruleRepository;
        this.analysisSnapshotService = analysisSnapshotService;
        this.engineClient = engineClient;
        this.secretMaskingService = secretMaskingService;
        this.metrics = metrics;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        // The engine accepts at most 500 files per request.
        this.batchSize = Math.max(1, Math.min(batchSize, 500));
    }

    @Async("analysisExecutor")
    public void executeAnalysisAsync(UUID analysisId, String traceId) {
        if (traceId != null) {
            MDC.put("traceId", traceId);
        }
        try {
            runAnalysis(analysisId, traceId);
        } finally {
            MDC.clear();
        }
    }

    void runAnalysis(UUID analysisId, String traceId) {
        Analysis analysis = analysisRepository.findById(analysisId)
                .orElseThrow(() -> new IllegalStateException("Análisis no encontrado"));
        if (analysis.getStatus() == AnalysisStatus.CANCELLED) {
            return;
        }

        analysis.setStatus(AnalysisStatus.RUNNING);
        analysis.setStartedAt(OffsetDateTime.now());
        analysisRepository.save(analysis);

        metrics.analysisStarted();
        long startedNanos = System.nanoTime();
        AnalysisStatus finalStatus = AnalysisStatus.CANCELLED;
        try {
            AnalysisSnapshotDto snapshot = analysisSnapshotService.getSnapshot(analysisId);
            int totalRules = Math.max(snapshot.rulesTotal(), 0);
            int executedRules = 0;

            UUID repositoryId = analysis.getRepository().getId();
            List<RepositoryFile> files = repositoryFileRepository.findByRepositoryId(repositoryId);
            String basePath = repositoryJpaRepository.findById(repositoryId)
                    .map(Repository::getPathInSandbox)
                    .orElse(null);
            log.info("Análisis iniciado analysisId={} reglas={} archivos={}", analysisId, totalRules, files.size());

            for (PolicySnapshotDto policySnapshot : snapshot.policies()) {
                for (RuleSnapshotDto ruleSnapshot : policySnapshot.rules()) {
                    if (isCancelled(analysisId)) {
                        log.info("Análisis cancelado analysisId={}", analysisId);
                        return;
                    }
                    executeRuleForFiles(analysis, policySnapshot, ruleSnapshot, files, basePath, traceId);
                    executedRules += 1;
                    updateProgress(analysisId, executedRules, totalRules);
                }
            }

            if (!isCancelled(analysisId)) {
                persistPolicyResults(analysis, snapshot);
                Analysis finalState = analysisRepository.findById(analysisId).orElseThrow();
                finalState.setStatus(AnalysisStatus.COMPLETED);
                finalState.setProgress(BigDecimal.valueOf(100));
                finalState.setCompletedAt(OffsetDateTime.now());
                analysisRepository.save(finalState);
                finalStatus = AnalysisStatus.COMPLETED;
                log.info("Análisis completado analysisId={} duracionMs={}", analysisId,
                        Duration.ofNanos(System.nanoTime() - startedNanos).toMillis());
            }
        } catch (Exception ex) {
            finalStatus = AnalysisStatus.FAILED;
            // The stack trace stays in the log, under the traceId of the request that started it.
            log.error("Análisis fallido analysisId={}", analysisId, ex);
            Analysis failed = analysisRepository.findById(analysisId).orElseThrow();
            failed.setStatus(AnalysisStatus.FAILED);
            failed.setErrorMessage(ex.getMessage());
            failed.setCompletedAt(OffsetDateTime.now());
            analysisRepository.save(failed);
        } finally {
            metrics.analysisFinished(finalStatus.name());
        }
    }

    private void executeRuleForFiles(
            Analysis analysis,
            PolicySnapshotDto policySnapshot,
            RuleSnapshotDto ruleSnapshot,
            List<RepositoryFile> files,
            String basePath,
            String traceId
    ) {
        Rule rule = ruleRepository.findById(ruleSnapshot.ruleId()).orElse(null);
        Policy policy = policyRepository.findById(policySnapshot.policyId()).orElse(null);

        if (files == null || files.isEmpty()) {
            registerRuleError(analysis, policy, rule, "NO_FILES", "No hay archivos inventariados para ejecutar reglas", null);
            return;
        }

        for (int from = 0; from < files.size(); from += batchSize) {
            if (isCancelled(analysis.getId())) {
                return;
            }
            List<RepositoryFile> batch = files.subList(from, Math.min(from + batchSize, files.size()));

            // The path sent to the engine -> the inventoried file it stands for.
            Map<String, RepositoryFile> byArtifactPath = new LinkedHashMap<>();
            for (RepositoryFile file : batch) {
                byArtifactPath.put(artifactPath(basePath, file), file);
            }

            ExecuteRuleBatchRequest request = new ExecuteRuleBatchRequest(
                    ruleSnapshot.ruleId().toString(),
                    ruleSnapshot.type(),
                    ruleSnapshot.payload(),
                    new ArrayList<>(byArtifactPath.keySet()),
                    ruleSnapshot.category(),
                    ruleSnapshot.severity(),
                    rule != null ? rule.getCweId() : null
            );

            ExecuteRuleResponse response;
            long requestStartedNanos = System.nanoTime();
            try {
                response = engineClient.executeRuleBatch(request, traceId);
            } catch (Exception ex) {
                metrics.ruleExecuted(ruleSnapshot.type(), false, Duration.ofNanos(System.nanoTime() - requestStartedNanos));
                log.warn("El motor no ejecutó la regla ruleId={} tipo={} archivos={}: {}",
                        ruleSnapshot.ruleId(), ruleSnapshot.type(), batch.size(), ex.getMessage());
                metrics.ruleError(ruleSnapshot.type(), "ENGINE_ERROR");
                registerRuleError(analysis, policy, rule, "ENGINE_ERROR",
                        ex.getMessage() + " (" + batch.size() + " archivos sin analizar con esta regla)", null);
                continue;
            }
            metrics.ruleExecuted(ruleSnapshot.type(), true, Duration.ofNanos(System.nanoTime() - requestStartedNanos));
            if (isCancelled(analysis.getId())) {
                return;
            }
            persistFindings(analysis, policy, rule, ruleSnapshot, byArtifactPath, response.findings());
            persistEngineErrors(analysis, policy, rule, ruleSnapshot.type(), byArtifactPath, response.errors());
        }
    }

    private static String artifactPath(String basePath, RepositoryFile file) {
        return (basePath != null && !basePath.isBlank())
                ? Paths.get(basePath, file.getPath()).toString()
                : file.getPath();
    }

    private void persistFindings(
            Analysis analysis,
            Policy policy,
            Rule rule,
            RuleSnapshotDto ruleSnapshot,
            Map<String, RepositoryFile> byArtifactPath,
            List<EngineFindingResponse> engineFindings
    ) {
        if (engineFindings == null || engineFindings.isEmpty()) {
            return;
        }
        List<Finding> findings = new ArrayList<>(engineFindings.size());
        for (EngineFindingResponse engineFinding : engineFindings) {
            RepositoryFile file = byArtifactPath.get(engineFinding.filePath());

            Finding finding = new Finding();
            finding.setAnalysis(analysis);
            finding.setRepository(analysis.getRepository());
            finding.setPolicy(policy);
            finding.setRule(rule);
            finding.setSeverity(resolveSeverity(engineFinding.severity(), ruleSnapshot.severity()));
            finding.setCategory(
                    (engineFinding.category() != null && !"UNKNOWN".equalsIgnoreCase(engineFinding.category()))
                            ? engineFinding.category()
                            : ruleSnapshot.category());
            // The repository-relative path, never the sandbox path the engine saw.
            finding.setFilePath(file != null ? file.getPath() : relativeToSandbox(engineFinding.filePath()));
            finding.setLineNumber(engineFinding.lineNumber());
            finding.setEvidenceSnippet(secretMaskingService.mask(engineFinding.evidenceSnippet()));
            finding.setCweId(engineFinding.cweId() != null
                    ? engineFinding.cweId()
                    : (rule != null ? rule.getCweId() : null));
            finding.setSuggestedAction(engineFinding.suggestedAction() != null
                    ? engineFinding.suggestedAction()
                    : extractSuggestedAction(rule));
            finding.setFileSha256(engineFinding.fileSha256() != null
                    ? engineFinding.fileSha256()
                    : (file != null ? file.getSha256() : null));
            findings.add(finding);
        }
        findingRepository.saveAll(findings);
    }

    private void persistEngineErrors(
            Analysis analysis,
            Policy policy,
            Rule rule,
            String ruleType,
            Map<String, RepositoryFile> byArtifactPath,
            List<EngineRuleErrorResponse> errors
    ) {
        if (errors == null || errors.isEmpty()) {
            return;
        }
        List<RuleExecutionError> entities = new ArrayList<>(errors.size());
        for (EngineRuleErrorResponse error : errors) {
            RepositoryFile file = error.filePath() != null ? byArtifactPath.get(error.filePath()) : null;
            String errorCode = error.errorCode() != null ? error.errorCode() : "ENGINE_RULE_ERROR";
            metrics.ruleError(ruleType, errorCode);
            entities.add(buildRuleError(
                    analysis,
                    policy,
                    rule,
                    errorCode,
                    error.message() != null ? error.message() : "Error de regla no especificado",
                    file != null ? file.getPath() : relativeToSandbox(error.filePath())
            ));
        }
        ruleExecutionErrorRepository.saveAll(entities);
    }

    /** Never exposes the sandbox location: an unknown path is reduced to its file name. */
    private static String relativeToSandbox(String path) {
        if (path == null) {
            return null;
        }
        java.nio.file.Path fileName = Paths.get(path).getFileName();
        return fileName != null ? fileName.toString() : null;
    }

    private void registerRuleError(Analysis analysis, Policy policy, Rule rule, String code, String message, String filePath) {
        if (isCancelled(analysis.getId())) {
            return;
        }
        ruleExecutionErrorRepository.save(buildRuleError(analysis, policy, rule, code, message, filePath));
    }

    private RuleExecutionError buildRuleError(Analysis analysis, Policy policy, Rule rule, String code,
                                              String message, String filePath) {
        RuleExecutionError error = new RuleExecutionError();
        error.setAnalysis(analysis);
        error.setPolicy(policy);
        error.setRule(rule);
        error.setErrorCode(code);
        error.setMessage(message);
        error.setFilePath(filePath);
        return error;
    }

    private void updateProgress(UUID analysisId, int executedRules, int totalRules) {
        Analysis analysis = analysisRepository.findById(analysisId).orElseThrow();
        if (analysis.getStatus() == AnalysisStatus.CANCELLED) {
            return;
        }
        analysis.setRulesExecuted(executedRules);
        analysis.setRulesTotal(totalRules);
        BigDecimal progress = totalRules == 0
                ? BigDecimal.valueOf(100)
                : BigDecimal.valueOf(executedRules)
                .multiply(BigDecimal.valueOf(100))
                .divide(BigDecimal.valueOf(totalRules), 2, RoundingMode.HALF_UP);
        analysis.setProgress(progress);
        analysisRepository.save(analysis);
    }

    /** Deletes and rewrites the policy results in one transaction: never a half-written set. */
    private void persistPolicyResults(Analysis analysis, AnalysisSnapshotDto snapshot) {
        transactionTemplate.executeWithoutResult(status -> {
            policyResultRepository.deleteByAnalysisId(analysis.getId());
            for (PolicySnapshotDto policySnapshot : snapshot.policies()) {
                long findingsCount = findingRepository.countByAnalysisIdAndPolicyId(analysis.getId(), policySnapshot.policyId());
                long highOrCritical = findingRepository.countByAnalysisIdAndPolicyIdAndSeverityIn(
                        analysis.getId(), policySnapshot.policyId(), HIGH_OR_CRITICAL
                );
                long lowOrMedium = findingRepository.countByAnalysisIdAndPolicyIdAndSeverityIn(
                        analysis.getId(), policySnapshot.policyId(), LOW_OR_MEDIUM
                );

                PolicyResult result = new PolicyResult();
                result.setAnalysis(analysis);
                result.setPolicy(policyRepository.findById(policySnapshot.policyId()).orElseThrow());
                result.setFindingsCount((int) findingsCount);
                result.setHighOrCriticalCount((int) highOrCritical);
                result.setLowOrMediumCount((int) lowOrMedium);
                result.setStatus(resolvePolicyStatus(findingsCount, highOrCritical));
                policyResultRepository.save(result);
            }
        });
    }

    private boolean isCancelled(UUID analysisId) {
        return analysisRepository.findById(analysisId)
                .map(a -> a.getStatus() == AnalysisStatus.CANCELLED)
                .orElse(true);
    }

    private PolicyComplianceStatus resolvePolicyStatus(long findingsCount, long highOrCritical) {
        if (findingsCount == 0) {
            return PolicyComplianceStatus.COMPLIANT;
        }
        if (highOrCritical > 0) {
            return PolicyComplianceStatus.NON_COMPLIANT;
        }
        return PolicyComplianceStatus.REQUIRES_REVIEW;
    }

    private SeverityLevel resolveSeverity(String engineSeverity, String fallback) {
        String value = engineSeverity != null ? engineSeverity : fallback;
        try {
            return SeverityLevel.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (Exception ex) {
            return SeverityLevel.MEDIUM;
        }
    }

    private String extractSuggestedAction(Rule rule) {
        if (rule == null || rule.getPayload() == null) {
            return null;
        }
        Object value = rule.getPayload().get("suggestedAction");
        return value != null ? value.toString() : null;
    }
}
