package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.AuditService;
import co.icesi.pdgseg.service.ReportService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** POST /api/v1/analyses/{id}/reports */
@WebMvcTest(AnalysisReportController.class)
@Import(SecurityConfig.class)
class AnalysisReportControllerTest {

    @Autowired MockMvc mockMvc;

    @MockBean ReportService reportService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean UserDetailsServiceImpl userDetailsService;
    @MockBean AuditService auditService;

    private final UUID analysisId = UUID.randomUUID();
    private final UUID reportId = UUID.randomUUID();

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void generate_completedAnalysis_returns201WithTheReportUrl() throws Exception {
        when(reportService.generate(analysisId, "auditor")).thenReturn(new ReportResponse(
                reportId, analysisId, ReportStatus.GENERATED, "a".repeat(64), OffsetDateTime.now()));

        mockMvc.perform(post("/api/v1/analyses/{id}/reports", analysisId))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "/api/v1/reports/" + reportId))
                .andExpect(jsonPath("$.id").value(reportId.toString()))
                .andExpect(jsonPath("$.status").value("GENERATED"))
                .andExpect(jsonPath("$.url").value("/api/v1/reports/" + reportId));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void generate_asSecurityAdmin_returns201() throws Exception {
        when(reportService.generate(analysisId, "admin")).thenReturn(new ReportResponse(
                reportId, analysisId, ReportStatus.GENERATED, "a".repeat(64), OffsetDateTime.now()));

        mockMvc.perform(post("/api/v1/analyses/{id}/reports", analysisId)).andExpect(status().isCreated());
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void generate_analysisNotCompleted_returns422StatingTheCurrentStatus() throws Exception {
        when(reportService.generate(analysisId, "auditor")).thenThrow(new UnprocessableEntityException(
                "Solo se pueden generar reportes de análisis completados (estado actual: CANCELLED)"));

        mockMvc.perform(post("/api/v1/analyses/{id}/reports", analysisId))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message")
                        .value("Solo se pueden generar reportes de análisis completados (estado actual: CANCELLED)"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void generate_unknownAnalysis_returns404() throws Exception {
        when(reportService.generate(analysisId, "auditor")).thenThrow(new ResourceNotFoundException("Análisis no encontrado"));

        mockMvc.perform(post("/api/v1/analyses/{id}/reports", analysisId)).andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void generate_asDeveloper_returns403() throws Exception {
        mockMvc.perform(post("/api/v1/analyses/{id}/reports", analysisId)).andExpect(status().isForbidden());
        verify(reportService, never()).generate(any(), any());
    }

    @Test
    void generate_withoutAuthentication_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/analyses/{id}/reports", analysisId)).andExpect(status().isUnauthorized());
    }
}
