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
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.observability.AnalysisMetrics;
import co.icesi.pdgseg.repository.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** One rule over the repository's files, sent to the engine in batches. */
class AnalysisExecutionServiceTest {

    private final AnalysisRepository analysisRepository = mock(AnalysisRepository.class);
    private final RepositoryFileRepository repositoryFileRepository = mock(RepositoryFileRepository.class);
    private final RepositoryJpaRepository repositoryJpaRepository = mock(RepositoryJpaRepository.class);
    private final FindingRepository findingRepository = mock(FindingRepository.class);
    private final PolicyResultRepository policyResultRepository = mock(PolicyResultRepository.class);
    private final RuleExecutionErrorRepository ruleExecutionErrorRepository = mock(RuleExecutionErrorRepository.class);
    private final PolicyRepository policyRepository = mock(PolicyRepository.class);
    private final RuleRepository ruleRepository = mock(RuleRepository.class);
    private final AnalysisSnapshotService snapshotService = mock(AnalysisSnapshotService.class);
    private final EngineClient engineClient = mock(EngineClient.class);
    private final SecretMaskingService masking = mock(SecretMaskingService.class);
    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

    private final UUID analysisId = UUID.randomUUID();
    private final UUID repositoryId = UUID.randomUUID();
    private final UUID policyId = UUID.randomUUID();
    private final UUID ruleId = UUID.randomUUID();
    private Analysis analysis;
    private AnalysisExecutionService service;

    @BeforeEach
    void setUp() {
        Repository repository = new Repository();
        ReflectionTestUtils.setField(repository, "id", repositoryId);
        repository.setPathInSandbox("/sandbox/repo");

        analysis = new Analysis();
        analysis.setId(analysisId);
        analysis.setRepository(repository);
        analysis.setStatus(AnalysisStatus.QUEUED);

        when(analysisRepository.findById(analysisId)).thenReturn(Optional.of(analysis));
        when(repositoryJpaRepository.findById(repositoryId)).thenReturn(Optional.of(repository));
        when(repositoryFileRepository.findByRepositoryId(repositoryId)).thenReturn(List.of(
                file("src/A.java"), file("src/B.java"), file("config/app.yml")));
        when(policyRepository.findById(policyId)).thenReturn(Optional.of(new Policy()));
        when(ruleRepository.findById(ruleId)).thenReturn(Optional.empty());
        when(masking.mask(any())).thenAnswer(inv -> inv.getArgument(0));
        when(snapshotService.getSnapshot(analysisId)).thenReturn(new AnalysisSnapshotDto(List.of(
                new PolicySnapshotDto(policyId, "SQLi", "SQL_INJECTION", List.of(
                        new RuleSnapshotDto(ruleId, "PATTERN_REGEX", "HIGH", "SQL_INJECTION",
                                Map.of("pattern", "executeQuery")))))));

        service = new AnalysisExecutionService(
                analysisRepository, repositoryFileRepository, repositoryJpaRepository, findingRepository,
                policyResultRepository, ruleExecutionErrorRepository, policyRepository, ruleRepository,
                snapshotService, engineClient, masking, new AnalysisMetrics(meterRegistry),
                mock(PlatformTransactionManager.class), 2);
    }

    private RepositoryFile file(String path) {
        RepositoryFile f = new RepositoryFile();
        f.setPath(path);
        f.setSha256("sha-" + path);
        return f;
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendsOneRequestPerBatchAndMapsFindingsAndErrorsBackToRepositoryPaths() {
        List<ExecuteRuleBatchRequest> requests = new ArrayList<>();
        when(engineClient.executeRuleBatch(any(), any())).thenAnswer(inv -> {
            ExecuteRuleBatchRequest request = inv.getArgument(0);
            requests.add(request);
            List<String> paths = request.artifactPaths();
            if (paths.size() == 2) {
                return new ExecuteRuleResponse(
                        List.of(new EngineFindingResponse(paths.get(1), 7, "stmt.executeQuery(sql)", null,
                                "SQL_INJECTION", "HIGH", "CWE-89", null)),
                        List.of(new EngineRuleErrorResponse("RULE_TIMEOUT", "timeout", paths.get(0))));
            }
            return new ExecuteRuleResponse(List.of(), List.of());
        });

        service.runAnalysis(analysisId, "trace-1");

        // 3 files, batches of 2 -> 2 requests instead of 3.
        assertThat(requests).hasSize(2);
        assertThat(requests.get(0).artifactPaths()).hasSize(2);
        assertThat(requests.get(0).severity()).isEqualTo("HIGH");

        ArgumentCaptor<List<Finding>> findings = ArgumentCaptor.forClass(List.class);
        verify(findingRepository).saveAll(findings.capture());
        Finding finding = findings.getValue().get(0);
        assertThat(finding.getFilePath()).isEqualTo("src/B.java");
        assertThat(finding.getLineNumber()).isEqualTo(7);
        assertThat(finding.getSeverity()).isEqualTo(SeverityLevel.HIGH);
        assertThat(finding.getFileSha256()).isEqualTo("sha-src/B.java");

        ArgumentCaptor<List<RuleExecutionError>> errors = ArgumentCaptor.forClass(List.class);
        verify(ruleExecutionErrorRepository).saveAll(errors.capture());
        assertThat(errors.getValue()).singleElement().satisfies(e -> {
            assertThat(e.getErrorCode()).isEqualTo("RULE_TIMEOUT");
            assertThat(e.getFilePath()).isEqualTo("src/A.java");
        });

        assertThat(analysis.getStatus()).isEqualTo(AnalysisStatus.COMPLETED);
        verify(policyResultRepository).deleteByAnalysisId(analysisId);
        verify(policyResultRepository).save(any(PolicyResult.class));

        // Metrics: one engine request timed per batch, the engine's error counted by its code.
        assertThat(executed("COMPLETED")).isEqualTo(1.0);
        assertThat(meterRegistry.get("analyses.running.current").gauge().value()).isZero();
        assertThat(meterRegistry.get("rule.execution.duration")
                .tags("ruleType", "PATTERN_REGEX", "outcome", "success").timer().count()).isEqualTo(2);
        assertThat(meterRegistry.get("rule.execution.errors")
                .tags("ruleType", "PATTERN_REGEX", "errorCode", "RULE_TIMEOUT").counter().count()).isEqualTo(1.0);
    }

    @Test
    void anEngineFailureOnOneBatchIsRecordedOnceAndTheRestContinues() {
        when(engineClient.executeRuleBatch(any(), any()))
                .thenThrow(new IllegalStateException("No se pudo ejecutar regla en motor Python"))
                .thenReturn(new ExecuteRuleResponse(List.of(), List.of()));

        service.runAnalysis(analysisId, "trace-2");

        verify(engineClient, times(2)).executeRuleBatch(any(), any());
        ArgumentCaptor<RuleExecutionError> error = ArgumentCaptor.forClass(RuleExecutionError.class);
        verify(ruleExecutionErrorRepository).save(error.capture());
        assertThat(error.getValue().getErrorCode()).isEqualTo("ENGINE_ERROR");
        assertThat(error.getValue().getMessage()).contains("2 archivos");
        assertThat(analysis.getStatus()).isEqualTo(AnalysisStatus.COMPLETED);
        assertThat(meterRegistry.get("rule.execution.errors")
                .tags("errorCode", "ENGINE_ERROR").counter().count()).isEqualTo(1.0);
        assertThat(meterRegistry.get("rule.execution.duration").tags("outcome", "error").timer().count())
                .isEqualTo(1);
    }

    @Test
    void aFailedAnalysisIsCountedAsFailedAndStopsCountingAsRunning() {
        when(snapshotService.getSnapshot(analysisId)).thenThrow(new IllegalStateException("snapshot corrupto"));

        service.runAnalysis(analysisId, "trace-4");

        assertThat(analysis.getStatus()).isEqualTo(AnalysisStatus.FAILED);
        assertThat(executed("FAILED")).isEqualTo(1.0);
        assertThat(executed("COMPLETED")).isZero();
        assertThat(meterRegistry.get("analyses.running.current").gauge().value()).isZero();
    }

    @Test
    void stopsSendingBatchesOnceTheAnalysisIsCancelled() {
        when(engineClient.executeRuleBatch(any(), any())).thenAnswer(inv -> {
            analysis.setStatus(AnalysisStatus.CANCELLED);
            return new ExecuteRuleResponse(List.of(), List.of());
        });

        service.runAnalysis(analysisId, "trace-3");

        verify(engineClient, times(1)).executeRuleBatch(any(), any());
        verify(policyResultRepository, never()).save(any());
        assertThat(analysis.getStatus()).isEqualTo(AnalysisStatus.CANCELLED);
        assertThat(executed("CANCELLED")).isEqualTo(1.0);
    }

    private double executed(String status) {
        return meterRegistry.get("analyses.executed").tag("status", status).counter().count();
    }
}
