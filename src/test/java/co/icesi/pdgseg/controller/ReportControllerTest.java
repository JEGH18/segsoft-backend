package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.entity.enums.ReportStatus;
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
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

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
                PDF_BYTES, MediaType.APPLICATION_PDF, "segsoft-report-" + reportId + ".pdf"));
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
                sarif, MediaType.valueOf("application/sarif+json"), "segsoft-report-" + reportId + ".sarif"));

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId).param("format", "sarif"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/sarif+json"))
                .andExpect(header().string("Content-Disposition",
                        "attachment; filename=\"segsoft-report-" + reportId + ".sarif\""))
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

    // ---- Generation ---------------------------------------------------------------------

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void generate_asAuditor_returns201() throws Exception {
        UUID analysisId = UUID.randomUUID();
        when(reportService.generate(analysisId, "auditor")).thenReturn(new ReportResponse(
                reportId, analysisId, ReportStatus.GENERATED, "a".repeat(64), OffsetDateTime.now()));

        mockMvc.perform(post("/api/v1/reports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"analysisId\":\"" + analysisId + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(reportId.toString()))
                .andExpect(jsonPath("$.status").value("GENERATED"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void generate_withoutAnalysisId_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/reports").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void generate_analysisNotCompleted_returns422() throws Exception {
        UUID analysisId = UUID.randomUUID();
        when(reportService.generate(analysisId, "auditor"))
                .thenThrow(new UnprocessableEntityException("Solo análisis COMPLETED"));

        mockMvc.perform(post("/api/v1/reports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"analysisId\":\"" + analysisId + "\"}"))
                .andExpect(status().isUnprocessableEntity());
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void generate_asDeveloper_returns403() throws Exception {
        mockMvc.perform(post("/api/v1/reports")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"analysisId\":\"" + UUID.randomUUID() + "\"}"))
                .andExpect(status().isForbidden());
        verify(reportService, never()).generate(any(), any());
    }
}
