package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.dto.response.AnalysisResponse;
import co.icesi.pdgseg.dto.response.AnalysisResultsResponse;
import co.icesi.pdgseg.dto.response.FindingResponse;
import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicyResult;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.entity.enums.SourceType;
import co.icesi.pdgseg.exception.ReportIntegrityException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.exception.UnsupportedExportFormatException;
import co.icesi.pdgseg.export.ReportExporter;
import co.icesi.pdgseg.export.ReportExporterRegistry;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.PolicyResultRepository;
import co.icesi.pdgseg.repository.ReportRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.math.BigDecimal;
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
    @Mock AuditService auditService;
    @Mock ReportExporter pdfExporter;

    private final ObjectMapper objectMapper = Jackson2ObjectMapperBuilder.json().build();
    private ReportService service;

    private final UUID analysisId = UUID.randomUUID();
    private final UUID reportId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        lenient().when(pdfExporter.format()).thenReturn("pdf");
        lenient().when(pdfExporter.mediaType()).thenReturn(MediaType.APPLICATION_PDF);
        lenient().when(pdfExporter.fileExtension()).thenReturn("pdf");
        service = new ReportService(reportRepository, analysisRepository, policyResultRepository, userRepository,
                analysisService, new SecretMaskingService(), new ReportExporterRegistry(List.of(pdfExporter)),
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
                .hasMessageContaining("COMPLETED");
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
                .isEqualTo(ReportService.sha256Hex(report.getContentJson()));
        assertThat(response.checksum()).isEqualTo(report.getChecksum());
        assertThat(response.id()).isEqualTo(reportId);

        assertThat(report.getContentJson())
                .doesNotContain("live_raw_secret_123")
                .doesNotContain("t0ps3cret")
                .contains("api_key=*****");

        ReportContent content = objectMapper.readValue(report.getContentJson(), ReportContent.class);
        assertThat(content.categoryCoverage()).extracting(ReportContent.CategoryCoverage::category)
                .containsExactly("SQL_INJECTION", "XSS", "AUTHENTICATION_FAILURE", "INSECURE_DATA_HANDLING",
                        "DEPENDENCY_VULNERABILITY");
        assertThat(content.summary().nonCompliantPolicies()).isEqualTo(1);
        assertThat(content.summary().findingsBySeverity()).containsEntry("CRITICAL", 1).containsEntry("LOW", 0);
        assertThat(content.metadata().generatedBy()).isEqualTo("auditor");
        assertThat(content.metadata().gitUrl()).isEqualTo("https://bot:*****@github.com/acme/app.git");
        verify(auditService).record(eq("REPORT_GENERATED"), eq("auditor"), isNull(), anyMap());
    }

    // ---- export ------------------------------------------------------------------------

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
        report.setContentJson(report.getContentJson().replace("\"totalFindings\":0", "\"totalFindings\":99"));
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
                List.of(), List.of(), List.of());
        String json = objectMapper.writeValueAsString(content);

        Report report = new Report();
        report.setId(reportId);
        report.setStatus(ReportStatus.GENERATED);
        report.setContentJson(json);
        report.setChecksum(ReportService.sha256Hex(json));
        report.setGeneratedAt(OffsetDateTime.now());
        return report;
    }
}
