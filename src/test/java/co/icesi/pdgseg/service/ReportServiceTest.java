package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.dto.response.AnalysisResponse;
import co.icesi.pdgseg.dto.response.AnalysisResultsResponse;
import co.icesi.pdgseg.dto.response.FindingResponse;
import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.dto.snapshot.AnalysisSnapshotDto;
import co.icesi.pdgseg.dto.snapshot.PolicySnapshotDto;
import co.icesi.pdgseg.dto.snapshot.RuleSnapshotDto;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicyResult;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.entity.Rule;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.entity.enums.SourceType;
import co.icesi.pdgseg.exception.ExportTooLargeException;
import co.icesi.pdgseg.exception.ReportIntegrityException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.SarifValidationException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.exception.UnsupportedExportFormatException;
import co.icesi.pdgseg.export.ReportExporter;
import co.icesi.pdgseg.export.ReportExporterRegistry;
import co.icesi.pdgseg.export.cache.ExportFileCache;
import co.icesi.pdgseg.export.cache.ExportSizeLimit;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.PolicyResultRepository;
import co.icesi.pdgseg.repository.ReportRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReportServiceTest {

    @Mock ReportRepository reportRepository;
    @Mock AnalysisRepository analysisRepository;
    @Mock PolicyResultRepository policyResultRepository;
    @Mock UserRepository userRepository;
    @Mock AnalysisService analysisService;
    @Mock AnalysisSnapshotService analysisSnapshotService;
    @Mock RuleRepository ruleRepository;
    @Mock AuditService auditService;
    @Mock ReportExporter pdfExporter;
    @TempDir Path cacheDir;

    private final ObjectMapper objectMapper = Jackson2ObjectMapperBuilder.json().build();
    private ReportService service;

    private final UUID analysisId = UUID.randomUUID();
    private final UUID reportId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        lenient().when(pdfExporter.format()).thenReturn("pdf");
        lenient().when(pdfExporter.mediaType()).thenReturn(MediaType.APPLICATION_PDF);
        lenient().when(pdfExporter.fileExtension()).thenReturn("pdf");
        service = newService(List.of(pdfExporter), 50);
    }

    /** Real filesystem export cache in a per-test temp directory. */
    private ReportService newService(List<ReportExporter> exporters, long maxExportSizeMb) {
        SecretMaskingService masking = new SecretMaskingService();
        ReportGeneratorService generator = new ReportGeneratorService(analysisService, policyResultRepository,
                ruleRepository, analysisSnapshotService, masking);
        return new ReportService(reportRepository, analysisRepository, userRepository, generator,
                new StructuredReportMapper(masking), new ReportExporterRegistry(exporters),
                new ExportFileCache(cacheDir.toString(), Duration.ofHours(1)), new ExportSizeLimit(maxExportSizeMb),
                auditService, objectMapper);
    }

    // ---- generate --------------------------------------------------------------------

    @Test
    void generate_unknownAnalysis_throwsNotFound() {
        when(analysisRepository.findById(analysisId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.generate(analysisId, "auditor"))
                .isInstanceOf(ResourceNotFoundException.class);
        verify(reportRepository, never()).save(any());
    }

    @Test
    void generate_analysisNotCompleted_isRejected() {
        Analysis running = analysis(AnalysisStatus.RUNNING);
        when(analysisRepository.findById(analysisId)).thenReturn(Optional.of(running));

        assertThatThrownBy(() -> service.generate(analysisId, "auditor"))
                .isInstanceOf(UnprocessableEntityException.class)
                .hasMessage("Solo se pueden generar reportes de análisis completados (estado actual: RUNNING)");
        verify(reportRepository, never()).save(any());
    }

    @Test
    void generate_completedAnalysis_freezesMaskedContentWithItsChecksum() throws Exception {
        stubCompletedAnalysis("config: api_key=live_raw_secret_123");
        when(reportRepository.save(any(Report.class))).thenAnswer(inv -> {
            Report report = inv.getArgument(0);
            report.setId(reportId);
            return report;
        });

        ReportResponse response = service.generate(analysisId, "auditor");

        ArgumentCaptor<Report> saved = ArgumentCaptor.forClass(Report.class);
        verify(reportRepository).save(saved.capture());
        Report report = saved.getValue();
        assertThat(report.getStatus()).isEqualTo(ReportStatus.GENERATED);
        assertThat(report.getChecksum())
                .hasSize(64)
                .isEqualTo(ReportChecksum.of(report.getContent()));
        assertThat(response.checksum()).isEqualTo(report.getChecksum());
        assertThat(response.id()).isEqualTo(reportId);

        assertThat(report.getContent())
                .doesNotContain("live_raw_secret_123")
                .doesNotContain("t0ps3cret")
                .contains("api_key=*****");

        ReportContent content = objectMapper.readValue(report.getContent(), ReportContent.class);
        assertThat(content.categoryCoverage()).extracting(ReportContent.CategoryCoverage::category)
                .containsExactly("SQL_INJECTION", "XSS", "AUTHENTICATION_FAILURE", "INSECURE_DATA_HANDLING",
                        "DEPENDENCY_VULNERABILITY");
        assertThat(content.summary().nonCompliantPolicies()).isEqualTo(1);
        assertThat(content.summary().findingsBySeverity()).containsEntry("CRITICAL", 1).containsEntry("LOW", 0);
        assertThat(content.metadata().generatedBy()).isEqualTo("auditor");
        assertThat(content.metadata().gitUrl()).isEqualTo("https://bot:*****@github.com/acme/app.git");
        verify(auditService).record(eq("REPORT_GENERATED"), eq("auditor"), isNull(), anyMap());
    }

    @Test
    void generate_freezesTheRulesTheAnalysisExecuted() throws Exception {
        stubCompletedAnalysis("SELECT 1");
        UUID policyId = UUID.randomUUID();
        UUID ruleId = UUID.randomUUID();
        when(analysisSnapshotService.findSnapshot(analysisId)).thenReturn(Optional.of(new AnalysisSnapshotDto(List.of(
                new PolicySnapshotDto(policyId, "Consultas parametrizadas", "SQL_INJECTION", List.of(
                        new RuleSnapshotDto(ruleId, "PATTERN_REGEX", "CRITICAL", "SQL_INJECTION",
                                Map.of("pattern", "executeQuery", "description", "Concatenación en SQL token=abc123"))))))));
        Rule rule = mock(Rule.class);
        when(rule.getId()).thenReturn(ruleId);
        when(rule.getCweId()).thenReturn("CWE-89");
        when(ruleRepository.findAllById(List.of(ruleId))).thenReturn(List.of(rule));
        when(reportRepository.save(any(Report.class))).thenAnswer(inv -> {
            Report report = inv.getArgument(0);
            report.setId(reportId);
            return report;
        });

        service.generate(analysisId, "auditor");

        ArgumentCaptor<Report> saved = ArgumentCaptor.forClass(Report.class);
        verify(reportRepository).save(saved.capture());
        ReportContent content = objectMapper.readValue(saved.getValue().getContent(), ReportContent.class);
        assertThat(content.schemaVersion()).isEqualTo(ReportContent.CURRENT_SCHEMA_VERSION);
        assertThat(content.rules()).singleElement().satisfies(entry -> {
            assertThat(entry.ruleId()).isEqualTo(ruleId);
            assertThat(entry.policyName()).isEqualTo("Consultas parametrizadas");
            assertThat(entry.severity()).isEqualTo("CRITICAL");
            assertThat(entry.cweId()).isEqualTo("CWE-89");
            assertThat(entry.description()).isEqualTo("Concatenación en SQL token=*****");
        });
    }

    @Test
    void generate_withoutSnapshot_storesAnEmptyRuleList() throws Exception {
        stubCompletedAnalysis("SELECT 1");
        when(analysisSnapshotService.findSnapshot(analysisId)).thenReturn(Optional.empty());
        when(reportRepository.save(any(Report.class))).thenAnswer(inv -> {
            Report report = inv.getArgument(0);
            report.setId(reportId);
            return report;
        });

        service.generate(analysisId, "auditor");

        ArgumentCaptor<Report> saved = ArgumentCaptor.forClass(Report.class);
        verify(reportRepository).save(saved.capture());
        assertThat(objectMapper.readValue(saved.getValue().getContent(), ReportContent.class).rules()).isEmpty();
    }

    // ---- export ------------------------------------------------------------------------

    @Test
    void export_invalidSarif_propagatesAndIsNotAuditedAsExported() throws Exception {
        ReportExporter sarifExporter = mock(ReportExporter.class);
        when(sarifExporter.format()).thenReturn("sarif");
        when(sarifExporter.export(any())).thenThrow(new SarifValidationException(List.of("#: forced")));
        ReportService sarifService = newService(List.of(pdfExporter, sarifExporter), 50);
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(storedReport()));

        assertThatThrownBy(() -> sarifService.export(reportId, "sarif", "auditor"))
                .isInstanceOf(SarifValidationException.class);
        verify(auditService, never()).record(eq("REPORT_EXPORTED"), any(), any(), anyMap());
    }

    @Test
    void export_unsupportedFormat_isRejectedBeforeTouchingTheReport() {
        assertThatThrownBy(() -> service.export(reportId, "docx", "auditor"))
                .isInstanceOf(UnsupportedExportFormatException.class)
                .hasMessageContaining("pdf");
        verifyNoInteractions(reportRepository);
    }

    @Test
    void export_unknownReport_throwsNotFound() {
        when(reportRepository.findById(reportId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.export(reportId, "pdf", "auditor"))
                .isInstanceOf(ResourceNotFoundException.class);
        verify(pdfExporter, never()).export(any());
    }

    @Test
    void export_tamperedContent_isRejectedAndNoFileIsGenerated() throws Exception {
        Report report = storedReport();
        report.setContent(report.getContent().replace("\"totalFindings\":0", "\"totalFindings\":99"));
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(report));

        assertThatThrownBy(() -> service.export(reportId, "pdf", "auditor"))
                .isInstanceOf(ReportIntegrityException.class);
        verify(pdfExporter, never()).export(any());
        verify(auditService).record(eq("REPORT_INTEGRITY_VIOLATION"), eq("auditor"), isNull(), anyMap());
    }

    @Test
    void export_tamperedChecksum_isRejected() throws Exception {
        Report report = storedReport();
        report.setChecksum("0".repeat(64));
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(report));

        assertThatThrownBy(() -> service.export(reportId, "pdf", "auditor"))
                .isInstanceOf(ReportIntegrityException.class);
        verify(pdfExporter, never()).export(any());
    }

    @Test
    void export_validReport_rendersWithTheResolvedExporter() throws Exception {
        Report report = storedReport();
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(report));
        when(pdfExporter.export(any())).thenReturn(new byte[]{'%', 'P', 'D', 'F'});

        ExportedReport exported = service.export(reportId, "PDF", "auditor");

        assertThat(exported.fileName()).isEqualTo("segsoft-report-" + reportId + ".pdf");
        assertThat(exported.mediaType()).isEqualTo(MediaType.APPLICATION_PDF);
        assertThat(exported.content()).containsExactly('%', 'P', 'D', 'F');
        ArgumentCaptor<ReportDocument> document = ArgumentCaptor.forClass(ReportDocument.class);
        verify(pdfExporter).export(document.capture());
        assertThat(document.getValue().reportId()).isEqualTo(reportId);
        assertThat(document.getValue().checksum()).isEqualTo(report.getChecksum());
        assertThat(document.getValue().content().metadata().repositoryName()).isEqualTo("acme-app");
        verify(auditService).record(eq("REPORT_EXPORTED"), eq("auditor"), isNull(), anyMap());
    }

    // ---- export cache --------------------------------------------------------------------

    @Test
    void export_firstRequestIsAMissAndTheNextOneIsServedFromCache() throws Exception {
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(storedReport()));
        when(pdfExporter.export(any())).thenReturn(new byte[]{'%', 'P', 'D', 'F'});

        ExportedReport first = service.export(reportId, "pdf", "auditor");
        ExportedReport second = service.export(reportId, "pdf", "auditor");

        assertThat(first.cacheHit()).isFalse();
        assertThat(second.cacheHit()).isTrue();
        assertThat(second.content()).isEqualTo(first.content());
        assertThat(second.fileName()).isEqualTo("segsoft-report-" + reportId + ".pdf");
        verify(pdfExporter, times(1)).export(any());
        verify(auditService).record(eq("REPORT_EXPORTED"), eq("auditor"), isNull(),
                eq(Map.of("reportId", reportId.toString(), "format", "pdf", "cache", "MISS")));
        verify(auditService).record(eq("REPORT_EXPORTED"), eq("auditor"), isNull(),
                eq(Map.of("reportId", reportId.toString(), "format", "pdf", "cache", "HIT")));
    }

    @Test
    void export_integrityIsVerifiedEvenWhenTheFileIsCached() throws Exception {
        Report report = storedReport();
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(report));
        when(pdfExporter.export(any())).thenReturn(new byte[]{'%', 'P', 'D', 'F'});
        service.export(reportId, "pdf", "auditor");

        report.setContent(report.getContent().replace("\"totalFindings\":0", "\"totalFindings\":7"));

        assertThatThrownBy(() -> service.export(reportId, "pdf", "auditor"))
                .isInstanceOf(ReportIntegrityException.class);
    }

    @Test
    void export_aReportWhoseContentChangedGetsANewExport() throws Exception {
        Report report = storedReport();
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(report));
        when(pdfExporter.export(any())).thenReturn(new byte[]{1}, new byte[]{2});
        service.export(reportId, "pdf", "auditor");

        String changed = report.getContent().replace("\"acme-app\"", "\"acme-app-v2\"");
        report.setContent(changed);
        report.setChecksum(ReportChecksum.of(changed));
        ExportedReport after = service.export(reportId, "pdf", "auditor");

        assertThat(after.cacheHit()).isFalse();
        assertThat(after.content()).containsExactly(2);
        verify(pdfExporter, times(2)).export(any());
    }

    @Test
    void export_aFileAboveTheLimitIsRejectedAndNeverCached() throws Exception {
        ReportService limited = newService(List.of(pdfExporter), 1);
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(storedReport()));
        when(pdfExporter.export(any())).thenReturn(new byte[1024 * 1024 + 1]);

        assertThatThrownBy(() -> limited.export(reportId, "pdf", "auditor"))
                .isInstanceOf(ExportTooLargeException.class)
                .hasMessageContaining("1 MB");
        assertThatThrownBy(() -> limited.export(reportId, "pdf", "auditor"))
                .isInstanceOf(ExportTooLargeException.class);

        verify(pdfExporter, times(2)).export(any()); // regenerated: nothing was cached
        try (var files = java.nio.file.Files.list(cacheDir)) {
            assertThat(files).isEmpty();
        }
        verify(auditService, never()).record(eq("REPORT_EXPORTED"), any(), any(), anyMap());
    }

    @Test
    void export_aCachedFileAboveALoweredLimitIsRejected() throws Exception {
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(storedReport()));
        when(pdfExporter.export(any())).thenReturn(new byte[1024 * 1024 + 1]);
        service.export(reportId, "pdf", "auditor"); // cached under the 50 MB limit

        ReportService lowered = newService(List.of(pdfExporter), 1);

        assertThatThrownBy(() -> lowered.export(reportId, "pdf", "auditor"))
                .isInstanceOf(ExportTooLargeException.class);
        verify(pdfExporter, times(1)).export(any());
    }

    // ---- read ---------------------------------------------------------------------------

    @Test
    void get_returnsTheStructuredReportAfterVerifyingItsChecksum() throws Exception {
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(storedReport()));

        var report = service.get(reportId, ReportView.TECHNICAL, "auditor");

        assertThat(report.id()).isEqualTo(reportId);
        assertThat(report.status()).isEqualTo(ReportStatus.GENERATED);
        assertThat(report.view()).isEqualTo("technical");
        assertThat(report.metadata().repoName()).isEqualTo("acme-app");
        assertThat(report.metadata().generatedBy()).isEqualTo("auditor");
        assertThat(report.integrityVerified()).isTrue();
        assertThat(report.exportFormats()).containsExactly("pdf");
    }

    @Test
    void get_aTamperedReportIsRefusedAndAudited() throws Exception {
        Report report = storedReport();
        report.setContent(report.getContent().replace("\"acme-app\"", "\"otro-repo\""));
        when(reportRepository.findById(reportId)).thenReturn(Optional.of(report));

        assertThatThrownBy(() -> service.get(reportId, ReportView.TECHNICAL, "auditor"))
                .isInstanceOf(ReportIntegrityException.class);
        verify(auditService).record(eq("REPORT_INTEGRITY_VIOLATION"), eq("auditor"), isNull(), anyMap());
    }

    @Test
    void list_flagsATamperedReportWithoutHidingIt() throws Exception {
        Report tampered = storedReport();
        tampered.setChecksum("0".repeat(64));
        when(reportRepository.findAllByOrderByGeneratedAtDesc(any()))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(tampered)));

        var page = service.list(null, null, org.springframework.data.domain.PageRequest.of(0, 20));

        assertThat(page.getContent()).singleElement().satisfies(summary -> {
            assertThat(summary.integrityVerified()).isFalse();
            assertThat(summary.repositoryName()).isEqualTo("acme-app");
        });
    }

    @Test
    void list_filtersTheHistoryByRepository() throws Exception {
        UUID repositoryId = UUID.randomUUID();
        when(reportRepository.findByRepositoryId(eq(repositoryId.toString()), any()))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(storedReport())));

        assertThat(service.list(repositoryId, null, org.springframework.data.domain.PageRequest.of(0, 20))
                .getTotalElements()).isEqualTo(1);
        verify(reportRepository, never()).findAllByOrderByGeneratedAtDesc(any());
    }

    @Test
    void get_unknownReport_throwsNotFound() {
        when(reportRepository.findById(reportId)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(reportId, ReportView.TECHNICAL, "auditor"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ---- Fixtures ----------------------------------------------------------------------

    private Analysis analysis(AnalysisStatus status) {
        Repository repository = new Repository();
        repository.setOriginalName("acme-app");
        repository.setSourceType(SourceType.GIT);
        repository.setGitUrl("https://bot:t0ps3cret@github.com/acme/app.git");
        repository.setBranch("main");

        Analysis analysis = new Analysis();
        analysis.setId(analysisId);
        analysis.setRepository(repository);
        analysis.setStatus(status);
        analysis.setRulesExecuted(3);
        analysis.setRulesTotal(3);
        analysis.setStartedAt(OffsetDateTime.now().minusMinutes(1));
        analysis.setCompletedAt(OffsetDateTime.now());
        return analysis;
    }

    private void stubCompletedAnalysis(String rawSnippet) {
        when(analysisRepository.findById(analysisId)).thenReturn(Optional.of(analysis(AnalysisStatus.COMPLETED)));

        Policy sqlPolicy = policy("Consultas parametrizadas", Category.SQL_INJECTION);
        Policy xssPolicy = policy("CSP obligatoria", Category.XSS);
        when(policyResultRepository.findByAnalysisId(analysisId)).thenReturn(List.of(
                policyResult(sqlPolicy, PolicyComplianceStatus.NON_COMPLIANT, 1),
                policyResult(xssPolicy, PolicyComplianceStatus.COMPLIANT, 0)));

        // getResults() normally masks; the service must not rely on it.
        FindingResponse finding = new FindingResponse(UUID.randomUUID(), sqlPolicy.getId(), sqlPolicy.getName(),
                UUID.randomUUID(), SeverityLevel.CRITICAL, "SQL_INJECTION", "src/Dao.java", 10, rawSnippet,
                null, "CWE-89", "Usar consultas parametrizadas");
        AnalysisResponse analysisResponse = new AnalysisResponse(analysisId, null, AnalysisStatus.COMPLETED,
                3, 3, BigDecimal.valueOf(100), OffsetDateTime.now(), OffsetDateTime.now(), OffsetDateTime.now(),
                null, null);
        when(analysisService.getResults(analysisId)).thenReturn(new AnalysisResultsResponse(analysisResponse,
                List.of(finding), List.of(), List.of(), new BigDecimal("50.00"), new BigDecimal("40.00"), Map.of()));
    }

    private static Policy policy(String name, Category category) {
        Policy policy = new Policy();
        policy.setId(UUID.randomUUID());
        policy.setName(name);
        policy.setCategory(category);
        policy.setFramework(Framework.OWASP_TOP_10_2021);
        policy.setControlId("A03:2021");
        policy.setWeight(60);
        return policy;
    }

    private static PolicyResult policyResult(Policy policy, PolicyComplianceStatus status, int findings) {
        PolicyResult result = new PolicyResult();
        result.setPolicy(policy);
        result.setStatus(status);
        result.setFindingsCount(findings);
        result.setHighOrCriticalCount(findings);
        result.setLowOrMediumCount(0);
        return result;
    }

    /** A report whose checksum matches its content, as generate() would have stored it. */
    private Report storedReport() throws Exception {
        ReportContent content = new ReportContent(ReportContent.CURRENT_SCHEMA_VERSION,
                new ReportContent.Metadata(analysisId, null, "acme-app", "ZIP", null, null, null,
                        null, null, 0, 0, "auditor", OffsetDateTime.now()),
                new ReportContent.Summary(BigDecimal.ZERO, BigDecimal.ZERO, 0, 0, 0, 0, 0, Map.of(), 0),
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        String json = objectMapper.writeValueAsString(content);

        Report report = new Report();
        report.setId(reportId);
        report.setStatus(ReportStatus.GENERATED);
        report.setContent(json);
        report.setChecksum(ReportChecksum.of(json));
        report.setGeneratedAt(OffsetDateTime.now());
        return report;
    }
}
