package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.dto.response.PolicySetDetailResponse;
import co.icesi.pdgseg.dto.response.PolicySetPageResponse;
import co.icesi.pdgseg.dto.response.PolicySetPolicySummary;
import co.icesi.pdgseg.dto.response.PolicySetResponse;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicySetStatus;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.AuditService;
import co.icesi.pdgseg.service.PolicySetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * HTTP-layer coverage for the Gherkin scenarios' status codes: this is a
 * @WebMvcTest slice, which does NOT load @Service beans -- GlobalExceptionHandler
 * (loaded regardless of which controller is under test) requires AuditService in
 * its constructor, so it must be @MockBean'd here or the whole context fails to
 * start (the known "≈25 tests in red" issue tracked for this codebase).
 */
@WebMvcTest(PolicySetController.class)
@Import(SecurityConfig.class)
class PolicySetControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockBean PolicySetService policySetService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean UserDetailsServiceImpl userDetailsService;
    @MockBean AuditService auditService;

    private PolicySetResponse stubResponse(UUID id, String name, PolicySetStatus status, int version) {
        return new PolicySetResponse(
            id, name, "Conjunto base para validación de proyectos de grado", status, version,
            List.of(UUID.randomUUID(), UUID.randomUUID()),
            List.of("Política A", "Política B"),
            OffsetDateTime.now(), UUID.randomUUID(), OffsetDateTime.now()
        );
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicySet_asAdmin_returns201() throws Exception {
        UUID p1 = UUID.randomUUID(), p2 = UUID.randomUUID();
        UUID setId = UUID.randomUUID();
        when(policySetService.create(any(), eq("admin")))
            .thenReturn(stubResponse(setId, "Perfil PDG ICESI", PolicySetStatus.ACTIVE, 1));

        String body = """
            {"name":"Perfil PDG ICESI","description":"Conjunto base para validación de proyectos de grado",
             "policyIds":["%s","%s"]}
            """.formatted(p1, p2);

        mockMvc.perform(post("/api/v1/policy-sets")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.name").value("Perfil PDG ICESI"))
            .andExpect(jsonPath("$.status").value("ACTIVE"))
            .andExpect(jsonPath("$.version").value(1));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicySet_invalidPolicy_returns400() throws Exception {
        UUID badId = UUID.randomUUID();
        when(policySetService.create(any(), any()))
            .thenThrow(new BusinessValidationException("La política '" + badId + "' no existe o no está activa"));

        String body = """
            {"name":"Set X","description":"desc","policyIds":["%s"]}
            """.formatted(badId);

        mockMvc.perform(post("/api/v1/policy-sets")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message", org.hamcrest.Matchers.containsString("no existe o no está activa")));
    }

    @Test
    void createPolicySet_withoutAuth_returns401or403() throws Exception {
        mockMvc.perform(post("/api/v1/policy-sets")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"x\",\"policyIds\":[]}"))
            .andExpect(result -> {
                int status = result.getResponse().getStatus();
                org.assertj.core.api.Assertions.assertThat(status).isIn(401, 403);
            });
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void createPolicySet_wrongRole_returns403() throws Exception {
        mockMvc.perform(post("/api/v1/policy-sets")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"x\",\"policyIds\":[\"" + UUID.randomUUID() + "\"]}"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void patchPolicySet_incrementsVersion_returns200() throws Exception {
        UUID setId = UUID.randomUUID();
        when(policySetService.patch(eq(setId), any(), eq("admin")))
            .thenReturn(stubResponse(setId, "Perfil PDG ICESI", PolicySetStatus.ACTIVE, 2));

        mockMvc.perform(patch("/api/v1/policy-sets/{id}", setId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"policyIds\":[\"" + UUID.randomUUID() + "\"]}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.version").value(2));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void archivePolicySet_success_returns204() throws Exception {
        UUID setId = UUID.randomUUID();

        mockMvc.perform(delete("/api/v1/policy-sets/{id}", setId).with(csrf()))
            .andExpect(status().isNoContent());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void archivePolicySet_blockedByRunningAnalysis_returns409() throws Exception {
        UUID setId = UUID.randomUUID();
        org.mockito.Mockito.doThrow(new ConflictException(
                "No se puede archivar: existen análisis en curso que dependen de este Policy Set"))
            .when(policySetService).archive(eq(setId), eq("admin"));

        mockMvc.perform(delete("/api/v1/policy-sets/{id}", setId).with(csrf()))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.message", org.hamcrest.Matchers.containsString("análisis en curso")));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void listPolicySets_anyAuthenticatedRole_returns200() throws Exception {
        when(policySetService.list(isNull(), isNull(), any(Pageable.class)))
            .thenReturn(new PolicySetPageResponse(List.of(), 0, 10, 0, 0, null));

        mockMvc.perform(get("/api/v1/policy-sets"))
            .andExpect(status().isOk());
    }

    // ── "Listar y consultar el catálogo de Policy Sets" ──────────────────

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void listPolicySets_defaultsToActive_returnsPaginationMetadata() throws Exception {
        when(policySetService.list(isNull(), isNull(), any(Pageable.class)))
            .thenReturn(new PolicySetPageResponse(
                List.of(stubResponse(UUID.randomUUID(), "Perfil A", PolicySetStatus.ACTIVE, 1)),
                0, 10, 9, 1, null));

        mockMvc.perform(get("/api/v1/policy-sets"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.page").value(0))
            .andExpect(jsonPath("$.size").value(10))
            .andExpect(jsonPath("$.totalElements").value(9))
            .andExpect(jsonPath("$.content", org.hamcrest.Matchers.hasSize(1)));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void listPolicySets_statusArchived_forwardsFilterToService() throws Exception {
        when(policySetService.list(eq(PolicySetStatus.ARCHIVED), isNull(), any(Pageable.class)))
            .thenReturn(new PolicySetPageResponse(List.of(), 0, 10, 3, 1, null));

        mockMvc.perform(get("/api/v1/policy-sets").param("status", "ARCHIVED"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(3));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void listPolicySets_emptyCatalog_includesCreateOneMessage() throws Exception {
        when(policySetService.list(isNull(), isNull(), any(Pageable.class)))
            .thenReturn(new PolicySetPageResponse(List.of(), 0, 10, 0, 0,
                "No hay Policy Sets registrados. Cree uno para estandarizar sus análisis."));

        mockMvc.perform(get("/api/v1/policy-sets"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content", org.hamcrest.Matchers.hasSize(0)))
            .andExpect(jsonPath("$.message").value(
                "No hay Policy Sets registrados. Cree uno para estandarizar sus análisis."));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void listPolicySets_searchByName_forwardsToService() throws Exception {
        when(policySetService.list(isNull(), eq("ICESI"), any(Pageable.class)))
            .thenReturn(new PolicySetPageResponse(
                List.of(stubResponse(UUID.randomUUID(), "Perfil PDG ICESI", PolicySetStatus.ACTIVE, 1)),
                0, 10, 1, 1, null));

        mockMvc.perform(get("/api/v1/policy-sets").param("search", "ICESI"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].name").value("Perfil PDG ICESI"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void getPolicySetDetail_returnsPoliciesCoverageAndUsageCount() throws Exception {
        UUID setId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();

        Map<Category, Long> coverage = new LinkedHashMap<>();
        for (Category c : Category.values()) coverage.put(c, c == Category.SQL_INJECTION ? 1L : 0L);

        when(policySetService.findDetailById(setId)).thenReturn(new PolicySetDetailResponse(
            setId, "ps-pdg-icesi", "desc", PolicySetStatus.ACTIVE, 1,
            List.of(policyId), List.of("Prevención de SQL Injection"),
            List.of(new PolicySetPolicySummary(policyId, "Prevención de SQL Injection",
                Framework.OWASP_TOP_10_2021, Category.SQL_INJECTION)),
            coverage, 2,
            OffsetDateTime.now(), UUID.randomUUID(), OffsetDateTime.now()
        ));

        mockMvc.perform(get("/api/v1/policy-sets/{id}", setId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.name").value("ps-pdg-icesi"))
            .andExpect(jsonPath("$.policies", org.hamcrest.Matchers.hasSize(1)))
            .andExpect(jsonPath("$.policies[0].framework").value("OWASP_TOP_10_2021"))
            .andExpect(jsonPath("$.policies[0].category").value("SQL_INJECTION"))
            .andExpect(jsonPath("$.categoryCoverage.SQL_INJECTION").value(1))
            .andExpect(jsonPath("$.usageCount").value(2))
            .andExpect(jsonPath("$.version").value(1));
    }
}
