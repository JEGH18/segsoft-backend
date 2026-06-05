package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.engine.EngineFindingResponse;
import co.icesi.pdgseg.dto.engine.EngineRuleErrorResponse;
import co.icesi.pdgseg.dto.engine.ExecuteRuleRequest;
import co.icesi.pdgseg.dto.engine.ExecuteRuleResponse;
import co.icesi.pdgseg.dto.snapshot.AnalysisSnapshotDto;
import co.icesi.pdgseg.dto.snapshot.PolicySnapshotDto;
import co.icesi.pdgseg.dto.snapshot.RuleSnapshotDto;
import co.icesi.pdgseg.entity.*;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.repository.*;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.OffsetDateTime;
import java.util.*;

@Service
public class AnalysisExecutionService {

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
            SecretMaskingService secretMaskingService
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

    @Transactional
    protected void runAnalysis(UUID analysisId, String traceId) {
        Analysis analysis = analysisRepository.findById(analysisId)
                .orElseThrow(() -> new IllegalStateException("Análisis no encontrado"));
        if (analysis.getStatus() == AnalysisStatus.CANCELLED) {
            return;
        }

        analysis.setStatus(AnalysisStatus.RUNNING);
        analysis.setStartedAt(OffsetDateTime.now());
        analysisRepository.save(analysis);

        AnalysisSnapshotDto snapshot = analysisSnapshotService.getSnapshot(analysisId);
        int totalRules = Math.max(snapshot.rulesTotal(), 0);
        int executedRules = 0;

        UUID repositoryId = analysis.getRepository().getId();
        List<RepositoryFile> files = repositoryFileRepository.findByRepositoryId(repositoryId);
        String basePath = repositoryJpaRepository.findById(repositoryId)
                .map(Repository::getPathInSandbox)
                .orElse(null);

        try {
            for (PolicySnapshotDto policySnapshot : snapshot.policies()) {
                for (RuleSnapshotDto ruleSnapshot : policySnapshot.rules()) {
                    if (isCancelled(analysisId)) {
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
            }
        } catch (Exception ex) {
            Analysis failed = analysisRepository.findById(analysisId).orElseThrow();
            failed.setStatus(AnalysisStatus.FAILED);
            failed.setErrorMessage(ex.getMessage());
            failed.setCompletedAt(OffsetDateTime.now());
            analysisRepository.save(failed);
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

        List<String> ruleLanguages = ruleSnapshot.languages();
        boolean hasLanguageFilter = ruleLanguages != null && !ruleLanguages.isEmpty();

        for (RepositoryFile file : files) {
            if (isCancelled(analysis.getId())) {
                return;
            }
            if (hasLanguageFilter && !ruleLanguages.contains(file.getLanguage())) {
                continue;
            }
            try {
                String artifactPath = (basePath != null && !basePath.isBlank())
                        ? java.nio.file.Paths.get(basePath, file.getPath()).toString()
                        : file.getPath();
                ExecuteRuleRequest request = new ExecuteRuleRequest(
                        ruleSnapshot.ruleId().toString(),
                        ruleSnapshot.type(),
                        ruleSnapshot.payload(),
                        artifactPath
                );
                ExecuteRuleResponse response = engineClient.executeRule(request, traceId);
                List<EngineFindingResponse> deduped = deduplicateFindings(response.findings());
                persistFindings(analysis, policy, rule, file, ruleSnapshot, deduped);
                persistEngineErrors(analysis, policy, rule, file.getPath(), response.errors());
            } catch (Exception ex) {
                registerRuleError(analysis, policy, rule, "ENGINE_ERROR", ex.getMessage(), file.getPath());
            }
        }
    }

    private void persistFindings(
            Analysis analysis,
            Policy policy,
            Rule rule,
            RepositoryFile file,
            RuleSnapshotDto ruleSnapshot,
            List<EngineFindingResponse> findings
    ) {
        for (EngineFindingResponse engineFinding : findings) {
            if (isCancelled(analysis.getId())) {
                return;
            }
            Finding finding = new Finding();
            finding.setAnalysis(analysis);
            finding.setRepository(analysis.getRepository());
            finding.setPolicy(policy);
            finding.setRule(rule);
            finding.setSeverity(resolveSeverity(ruleSnapshot.severity(), engineFinding.severity()));
            finding.setCategory(
                    (engineFinding.category() != null && !"UNKNOWN".equalsIgnoreCase(engineFinding.category()))
                            ? engineFinding.category()
                            : ruleSnapshot.category());
            finding.setFilePath(file.getPath());
            finding.setLineNumber(engineFinding.lineNumber());
            finding.setEvidenceSnippet(secretMaskingService.mask(engineFinding.evidenceSnippet()));
            finding.setCweId(engineFinding.cweId());
            finding.setSuggestedAction(engineFinding.suggestedAction());
            finding.setFileSha256(engineFinding.fileSha256() != null ? engineFinding.fileSha256() : file.getSha256());
            findingRepository.save(finding);
        }
    }

    private void persistEngineErrors(
            Analysis analysis,
            Policy policy,
            Rule rule,
            String filePath,
            List<EngineRuleErrorResponse> errors
    ) {
        if (errors == null || errors.isEmpty()) {
            return;
        }
        for (EngineRuleErrorResponse error : errors) {
            registerRuleError(
                    analysis,
                    policy,
                    rule,
                    error.errorCode() != null ? error.errorCode() : "ENGINE_RULE_ERROR",
                    error.message() != null ? error.message() : "Error de regla no especificado",
                    filePath
            );
        }
    }

    private void registerRuleError(Analysis analysis, Policy policy, Rule rule, String code, String message, String filePath) {
        if (isCancelled(analysis.getId())) {
            return;
        }
        RuleExecutionError error = new RuleExecutionError();
        error.setAnalysis(analysis);
        error.setPolicy(policy);
        error.setRule(rule);
        error.setErrorCode(code);
        error.setMessage(message);
        error.setFilePath(filePath);
        ruleExecutionErrorRepository.save(error);
    }

    @Transactional
    protected void updateProgress(UUID analysisId, int executedRules, int totalRules) {
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

    @Transactional
    protected void persistPolicyResults(Analysis analysis, AnalysisSnapshotDto snapshot) {
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
    }

    @Transactional(readOnly = true)
    protected boolean isCancelled(UUID analysisId) {
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

    private List<EngineFindingResponse> deduplicateFindings(List<EngineFindingResponse> findings) {
        Set<String> seen = new LinkedHashSet<>();
        List<EngineFindingResponse> result = new ArrayList<>();
        for (EngineFindingResponse f : findings) {
            String key = f.lineNumber() + "|" + (f.evidenceSnippet() != null ? f.evidenceSnippet() : "");
            if (seen.add(key)) {
                result.add(f);
            }
        }
        return result;
    }

    private SeverityLevel resolveSeverity(String engineSeverity, String fallback) {
        String value = engineSeverity != null ? engineSeverity : fallback;
        try {
            return SeverityLevel.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (Exception ex) {
            return SeverityLevel.MEDIUM;
        }
    }
}
