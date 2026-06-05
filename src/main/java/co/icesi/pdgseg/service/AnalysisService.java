package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.*;
import co.icesi.pdgseg.dto.snapshot.AnalysisSnapshotDto;
import co.icesi.pdgseg.entity.*;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.repository.*;
import co.icesi.pdgseg.repository.RepositoryRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.OffsetDateTime;
import java.util.*;

@Service
public class AnalysisService {

    private static final List<AnalysisStatus> ACTIVE_STATUSES = List.of(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING);

    private final AnalysisRepository analysisRepository;
    private final RepositoryRepository repositoryRepository;
    private final PolicySelectionRepository policySelectionRepository;
    private final AnalysisSnapshotService analysisSnapshotService;
    private final AnalysisExecutionService analysisExecutionService;
    private final FindingRepository findingRepository;
    private final PolicyResultRepository policyResultRepository;
    private final RuleExecutionErrorRepository ruleExecutionErrorRepository;
    private final UserRepository userRepository;
    private final SecretMaskingService secretMaskingService;

    public AnalysisService(
            AnalysisRepository analysisRepository,
            RepositoryRepository repositoryRepository,
            PolicySelectionRepository policySelectionRepository,
            AnalysisSnapshotService analysisSnapshotService,
            AnalysisExecutionService analysisExecutionService,
            FindingRepository findingRepository,
            PolicyResultRepository policyResultRepository,
            RuleExecutionErrorRepository ruleExecutionErrorRepository,
            UserRepository userRepository,
            SecretMaskingService secretMaskingService
    ) {
        this.analysisRepository = analysisRepository;
        this.repositoryRepository = repositoryRepository;
        this.policySelectionRepository = policySelectionRepository;
        this.analysisSnapshotService = analysisSnapshotService;
        this.analysisExecutionService = analysisExecutionService;
        this.findingRepository = findingRepository;
        this.policyResultRepository = policyResultRepository;
        this.ruleExecutionErrorRepository = ruleExecutionErrorRepository;
        this.userRepository = userRepository;
        this.secretMaskingService = secretMaskingService;
    }

    @Transactional
    public AnalysisResponse startAnalysis(UUID repositoryId, String username, String traceId) {
        Repository repository = repositoryRepository.findById(repositoryId)
                .orElseThrow(() -> new ResourceNotFoundException("Repositorio no encontrado"));

        PolicySelection selection = policySelectionRepository.findByRepositoryId(repositoryId)
                .orElseThrow(() -> new UnprocessableEntityException("El repositorio no tiene PolicySelection"));

        boolean hasActive = analysisRepository.existsByRepositoryIdAndStatusIn(repositoryId, ACTIVE_STATUSES);
        if (hasActive) {
            throw new ConflictException("Ya existe un análisis en estado QUEUED o RUNNING para este repositorio");
        }

        Analysis analysis = new Analysis();
        analysis.setRepository(repository);
        analysis.setStatus(AnalysisStatus.QUEUED);
        analysis.setRulesTotal(0);
        analysis.setRulesExecuted(0);
        analysis.setProgress(BigDecimal.ZERO);
        analysis.setCreatedBy(userRepository.findByUsername(username).orElse(null));
        analysis = analysisRepository.save(analysis);

        AnalysisSnapshotDto snapshot = analysisSnapshotService.createSnapshot(analysis, selection);
        analysis.setRulesTotal(snapshot.rulesTotal());
        analysisRepository.save(analysis);

        // Schedule async execution AFTER the transaction commits so the async thread
        // can read the analysis record from the DB (READ COMMITTED isolation).
        final UUID analysisId = analysis.getId();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                analysisExecutionService.executeAnalysisAsync(analysisId, traceId);
            }
        });
        return toAnalysisResponse(analysis);
    }

    @Transactional(readOnly = true)
    public AnalysisResponse getAnalysis(UUID id) {
        Analysis analysis = analysisRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Análisis no encontrado"));
        return toAnalysisResponse(analysis);
    }

    @Transactional(readOnly = true)
    public AnalysisResultsResponse getResults(UUID id) {
        Analysis analysis = analysisRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Análisis no encontrado"));

        List<FindingResponse> findings = findingRepository.findByAnalysisId(id).stream()
                .map(finding -> new FindingResponse(
                        finding.getId(),
                        finding.getPolicy() != null ? finding.getPolicy().getId() : null,
                        finding.getPolicy() != null ? finding.getPolicy().getName() : null,
                        finding.getRule() != null ? finding.getRule().getId() : null,
                        finding.getSeverity(),
                        finding.getCategory(),
                        finding.getFilePath(),
                        finding.getLineNumber(),
                        secretMaskingService.mask(finding.getEvidenceSnippet()),
                        finding.getFileSha256(),
                        finding.getCweId(),
                        finding.getSuggestedAction()
                ))
                .toList();

        List<PolicyResultResponse> policyResults = policyResultRepository.findByAnalysisId(id).stream()
                .map(result -> new PolicyResultResponse(
                        result.getPolicy().getId(),
                        result.getStatus(),
                        result.getFindingsCount(),
                        result.getHighOrCriticalCount(),
                        result.getLowOrMediumCount()
                ))
                .toList();

        List<RuleExecutionErrorResponse> errors = ruleExecutionErrorRepository.findByAnalysisId(id).stream()
                .map(error -> new RuleExecutionErrorResponse(
                        error.getId(),
                        error.getPolicy() != null ? error.getPolicy().getId() : null,
                        error.getRule() != null ? error.getRule().getId() : null,
                        error.getErrorCode(),
                        error.getMessage(),
                        error.getFilePath()
                ))
                .toList();

        BigDecimal compliancePercentage = calculateCompliancePercentage(policyResults);
        Map<String, BigDecimal> breakdown = calculateCategoryBreakdown(findings);

        return new AnalysisResultsResponse(
                toAnalysisResponse(analysis),
                findings,
                policyResults,
                errors,
                compliancePercentage,
                breakdown
        );
    }

    @Transactional
    public void cancelAnalysis(UUID id) {
        Analysis analysis = analysisRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Análisis no encontrado"));

        if (analysis.getStatus() == AnalysisStatus.COMPLETED || analysis.getStatus() == AnalysisStatus.FAILED) {
            return;
        }

        analysis.setStatus(AnalysisStatus.CANCELLED);
        analysis.setCancelledAt(OffsetDateTime.now());
        analysis.setProgress(BigDecimal.ZERO);
        analysisRepository.save(analysis);

        findingRepository.deleteByAnalysisId(id);
        policyResultRepository.deleteByAnalysisId(id);
        ruleExecutionErrorRepository.deleteByAnalysisId(id);
    }

    @Transactional(readOnly = true)
    public Analysis getAnalysisEntity(UUID id) {
        return analysisRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Análisis no encontrado"));
    }

    private AnalysisResponse toAnalysisResponse(Analysis analysis) {
        return new AnalysisResponse(
                analysis.getId(),
                analysis.getRepository().getId(),
                analysis.getStatus(),
                analysis.getRulesExecuted(),
                analysis.getRulesTotal(),
                analysis.getProgress(),
                analysis.getCreatedAt(),
                analysis.getStartedAt(),
                analysis.getCompletedAt(),
                analysis.getCancelledAt(),
                analysis.getErrorMessage()
        );
    }

    private BigDecimal calculateCompliancePercentage(List<PolicyResultResponse> policyResults) {
        if (policyResults.isEmpty()) {
            return BigDecimal.ZERO;
        }
        long compliant = policyResults.stream()
                .filter(result -> result.status() == PolicyComplianceStatus.COMPLIANT)
                .count();
        return BigDecimal.valueOf(compliant)
                .multiply(BigDecimal.valueOf(100))
                .divide(BigDecimal.valueOf(policyResults.size()), 2, RoundingMode.HALF_UP);
    }

    private Map<String, BigDecimal> calculateCategoryBreakdown(List<FindingResponse> findings) {
        if (findings.isEmpty()) {
            return Map.of();
        }
        Map<String, Long> counts = new HashMap<>();
        for (FindingResponse finding : findings) {
            counts.merge(finding.category(), 1L, Long::sum);
        }
        BigDecimal total = BigDecimal.valueOf(findings.size());
        Map<String, BigDecimal> breakdown = new HashMap<>();
        for (Map.Entry<String, Long> entry : counts.entrySet()) {
            BigDecimal percentage = BigDecimal.valueOf(entry.getValue())
                    .multiply(BigDecimal.valueOf(100))
                    .divide(total, 2, RoundingMode.HALF_UP);
            breakdown.put(entry.getKey(), percentage);
        }
        return breakdown;
    }
}
