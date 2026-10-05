package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.dto.response.ReportSummaryResponse;
import co.icesi.pdgseg.dto.response.StructuredReportResponse;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.export.ReportFixtures;
import co.icesi.pdgseg.service.ReportView;
import co.icesi.pdgseg.service.SecretMaskingService;
import co.icesi.pdgseg.service.StructuredReportMapper;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.exception.ExportTooLargeException;
import co.icesi.pdgseg.exception.ReportIntegrityException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.SarifValidationException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.exception.UnsupportedExportFormatException;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.AuditService;
import co.icesi.pdgseg.service.ReportService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * HTTP contract of the report endpoints (status codes, headers, roles). The
 * service is mocked; ReportServiceTest and ReportExportIntegrationTest cover
 * the behavior behind it.
 */
@WebMvcTest(ReportController.class)
@Import(SecurityConfig.class)
class ReportControllerTest {

    private static final byte[] PDF_BYTES = "%PDF-1.4 fake".getBytes();

    @Autowired MockMvc mockMvc;

    @MockBean ReportService reportService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean UserDetailsServiceImpl userDetailsService;
    @MockBean AuditService auditService;

    private final UUID reportId = UUID.fromString("0f8f7c1e-4c1a-4f3e-9d7a-2b6c1d0e9a11");

    private void stubPdfExport() {
        when(reportService.export(eq(reportId), eq("pdf"), anyString())).thenReturn(new ExportedReport(
                PDF_BYTES, MediaType.APPLICATION_PDF, "segsoft-report-" + reportId + ".pdf", false));
    }

    // ---- 200 -------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_pdf_asAuditor_returnsTheFileAsAttachment() throws Exception {
        stubPdfExport();

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "pdf"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF))
                .andExpect(header().string("Content-Disposition",
                        "attachment; filename=\"segsoft-report-" + reportId + ".pdf\""))
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(header().string("X-Cache", "MISS"))
                .andExpect(content().bytes(PDF_BYTES));
        verify(reportService).export(reportId, "pdf", "auditor");
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void export_pdf_asSecurityAdmin_returns200() throws Exception {
        stubPdfExport();

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "pdf"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_withoutFormat_defaultsToPdf() throws Exception {
        stubPdfExport();

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_sarif_returnsSarifJsonAsAttachment() throws Exception {
        byte[] sarif = "{\"version\":\"2.1.0\",\"runs\":[]}".getBytes();
        when(reportService.export(eq(reportId), eq("sarif"), anyString())).thenReturn(new ExportedReport(
                sarif, MediaType.valueOf("application/sarif+json"), "segsoft-report-" + reportId + ".sarif", true));

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "sarif"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/sarif+json"))
                .andExpect(header().string("Content-Disposition",
                        "attachment; filename=\"segsoft-report-" + reportId + ".sarif\""))
                .andExpect(header().string("X-Cache", "HIT"))
                .andExpect(content().bytes(sarif));
    }

    // ---- 400 / 404 / 409 / 500 ---------------------------------------------------------

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_unsupportedFormat_returns400WithSupportedFormats() throws Exception {
        when(reportService.export(eq(reportId), eq("docx"), anyString()))
                .thenThrow(new UnsupportedExportFormatException("docx", List.of("pdf")));

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "docx"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("UNSUPPORTED_FORMAT"))
                .andExpect(jsonPath("$.message").value(containsString("pdf")))
                .andExpect(jsonPath("$.supportedFormats[0]").value("pdf"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_unknownReport_returns404() throws Exception {
        when(reportService.export(eq(reportId), eq("pdf"), anyString()))
                .thenThrow(new ResourceNotFoundException("Reporte no encontrado"));

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "pdf"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("NOT_FOUND"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_checksumMismatch_returns409WithoutAFile() throws Exception {
        when(reportService.export(eq(reportId), eq("pdf"), anyString()))
                .thenThrow(new ReportIntegrityException("checksum no coincide"));

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "pdf"))
                .andExpect(status().isConflict())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().doesNotExist("Content-Disposition"))
                .andExpect(jsonPath("$.errorCode").value("REPORT_INTEGRITY_ERROR"));
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_invalidSarif_returns500WithTraceIdLogsItAndServesNoFile(CapturedOutput output) throws Exception {
        when(reportService.export(eq(reportId), eq("sarif"), anyString()))
                .thenThrow(new SarifValidationException(List.of("#/runs/0/results/0/level: critical is not a valid enum value")));

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId)
                        .param("format", "sarif")
                        .header("X-Trace-Id", "trace-sarif-invalido"))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().doesNotExist("Content-Disposition"))
                .andExpect(jsonPath("$.errorCode").value("SARIF_VALIDATION_ERROR"))
                .andExpect(jsonPath("$.traceId").value("trace-sarif-invalido"))
                // the violations are logged, never exposed to the client
                .andExpect(content().string(not(containsString("enum value"))));

        assertThat(output.getAll())
                .contains("SARIF inválido descartado")
                .contains("traceId=trace-sarif-invalido")
                .contains("critical is not a valid enum value");
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void export_aboveMaxExportSize_returns422StatingTheLimit() throws Exception {
        when(reportService.export(eq(reportId), eq("pdf"), anyString()))
                .thenThrow(new ExportTooLargeException(60L * 1024 * 1024, 50));

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "pdf"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(header().doesNotExist("Content-Disposition"))
                .andExpect(jsonPath("$.errorCode").value("EXPORT_TOO_LARGE"))
                .andExpect(jsonPath("$.maxSizeMb").value(50))
                .andExpect(jsonPath("$.message").value(containsString("50 MB")));
    }

    // ---- Report view ---------------------------------------------------------------------

    private ReportSummaryResponse summary() {
        return new ReportSummaryResponse(reportId, UUID.randomUUID(), ReportStatus.GENERATED, "a".repeat(64),
                OffsetDateTime.now(), "auditor", "acme-app", new BigDecimal("91.30"), new BigDecimal("92.50"),
                23, 2, java.util.Map.of("MEDIUM", 2), true, List.of("pdf", "sarif"));
    }

    private StructuredReportResponse structured(ReportView view) {
        Report report = new Report();
        report.setId(reportId);
        report.setStatus(ReportStatus.GENERATED);
        report.setChecksum("a".repeat(64));
        report.setGeneratedAt(OffsetDateTime.now());
        return new StructuredReportMapper(new SecretMaskingService())
                .toResponse(report, ReportFixtures.documentForSarif().content(), view, List.of("pdf", "sarif"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void get_returnsTheStructuredReportWithEverySection() throws Exception {
        when(reportService.get(reportId, ReportView.TECHNICAL, "auditor")).thenReturn(structured(ReportView.TECHNICAL));

        mockMvc.perform(get("/api/v1/reports/{id}", reportId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("GENERATED"))
                .andExpect(jsonPath("$.view").value("technical"))
                .andExpect(jsonPath("$.metadata.reportId").value(reportId.toString()))
                .andExpect(jsonPath("$.metadata.repoName").value("acme-payments"))
                .andExpect(jsonPath("$.executiveSummary.compliancePercentage").exists())
                .andExpect(jsonPath("$.policyResults").isArray())
                .andExpect(jsonPath("$.findingsBySeverity.CRITICAL.count").value(1))
                .andExpect(jsonPath("$.findingsBySeverity.CRITICAL.findings").isArray())
                .andExpect(jsonPath("$.claudeCodeSecurityCoverage.length()").value(5))
                .andExpect(jsonPath("$.frameworkCoverage").isArray())
                .andExpect(jsonPath("$.traceabilityReference.self").value("/api/v1/reports/" + reportId));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void get_executiveView_omitsTechnicalDetail() throws Exception {
        when(reportService.get(reportId, ReportView.EXECUTIVE, "auditor")).thenReturn(structured(ReportView.EXECUTIVE));

        mockMvc.perform(get("/api/v1/reports/{id}", reportId).param("view", "executive"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.view").value("executive"))
                .andExpect(jsonPath("$.policyResults").doesNotExist())
                .andExpect(jsonPath("$.findingsBySeverity.CRITICAL.count").value(1))
                .andExpect(jsonPath("$.findingsBySeverity.CRITICAL.findings").doesNotExist())
                .andExpect(jsonPath("$.executiveSummary.recommendations").isArray())
                .andExpect(jsonPath("$.claudeCodeSecurityCoverage.length()").value(5));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void get_unknownView_returns400() throws Exception {
        mockMvc.perform(get("/api/v1/reports/{id}", reportId).param("view", "resumen"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("technical, executive")));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void get_tamperedReport_returns409() throws Exception {
        when(reportService.get(eq(reportId), any(), anyString()))
                .thenThrow(new ReportIntegrityException("checksum no coincide"));

        mockMvc.perform(get("/api/v1/reports/{id}", reportId))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("REPORT_INTEGRITY_ERROR"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void list_returnsAPageOfReports() throws Exception {
        UUID repositoryId = UUID.randomUUID();
        when(reportService.list(eq(repositoryId), eq(null), any()))
                .thenReturn(new PageImpl<>(List.of(summary()), PageRequest.of(0, 20), 1));

        mockMvc.perform(get("/api/v1/reports").param("repositoryId", repositoryId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(reportId.toString()))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void reportView_isNotAvailableToDevelopers() throws Exception {
        mockMvc.perform(get("/api/v1/reports/{id}", reportId)).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/v1/reports")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void theFormerGenerationEndpointAnswers405() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/reports")
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.errorCode").value("METHOD_NOT_ALLOWED"))
                .andExpect(header().string("Allow", containsString("GET")));
    }

    // ---- Roles ---------------------------------------------------------------------------

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void export_asDeveloper_returns403() throws Exception {
        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "pdf"))
                .andExpect(status().isForbidden());
        verify(reportService, never()).export(any(), any(), any());
    }

    @Test
    void export_withoutAuthentication_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "pdf"))
                .andExpect(status().isUnauthorized());
        verify(reportService, never()).export(any(), any(), any());
    }
}
