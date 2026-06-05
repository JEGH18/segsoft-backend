package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.config.WebMvcConfig;
import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.filter.RateLimitInterceptor;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.PolicyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(PolicyController.class)
@Import({SecurityConfig.class, WebMvcConfig.class, RateLimitInterceptor.class})
class PolicyControllerSearchTest {

    @Autowired MockMvc mockMvc;

    @MockBean PolicyService policyService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean UserDetailsServiceImpl userDetailsService;

    private PolicyResponse stub(String name) {
        return new PolicyResponse(
            UUID.randomUUID(), name,
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.SQL_INJECTION, Framework.OWASP_TOP_10_2021, "A03:2021",
            PolicyStatus.ACTIVE, 1, 50, OffsetDateTime.now(), UUID.randomUUID()
        );
    }

    private Page<PolicyResponse> pageOf(PolicyResponse... items) {
        return new PageImpl<>(List.of(items), PageRequest.of(0, 10), items.length);
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void list_authenticated_returns200WithCacheHeader() throws Exception {
        when(policyService.search(any(), any(), any(), any(), any()))
            .thenReturn(pageOf(stub("P1"), stub("P2")));

        mockMvc.perform(get("/api/v1/policies"))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", containsString("max-age=60")))
            .andExpect(jsonPath("$.totalElements").value(2))
            .andExpect(jsonPath("$.content", hasSize(2)));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void list_withCategoryFilter_returns200() throws Exception {
        when(policyService.search(any(), any(), any(), any(), any()))
            .thenReturn(pageOf(stub("SQL Policy")));

        mockMvc.perform(get("/api/v1/policies")
                .param("category", "SQL_INJECTION")
                .param("status", "ACTIVE"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content[0].category").value("SQL_INJECTION"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void list_emptyBank_returns200WithEmptyContent() throws Exception {
        when(policyService.search(any(), any(), any(), any(), any()))
            .thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 10), 0));

        mockMvc.perform(get("/api/v1/policies"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(0))
            .andExpect(jsonPath("$.content").isEmpty());
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void list_sizeOver100_returns400() throws Exception {
        mockMvc.perform(get("/api/v1/policies").param("size", "200"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void list_invalidCategoryEnum_returns400() throws Exception {
        mockMvc.perform(get("/api/v1/policies").param("category", "INVALID_CATEGORY"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void list_unauthenticated_returns401or403() throws Exception {
        mockMvc.perform(get("/api/v1/policies"))
            .andExpect(status().is(anyOf(is(401), is(403))));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void getById_existingId_returns200() throws Exception {
        UUID id = UUID.randomUUID();
        when(policyService.findById(id)).thenReturn(stub("Detalle Política"));

        mockMvc.perform(get("/api/v1/policies/{id}", id))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.name").value("Detalle Política"))
            .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void getById_nonExistentId_returns404() throws Exception {
        UUID unknownId = UUID.randomUUID();
        when(policyService.findById(unknownId))
            .thenThrow(new ResourceNotFoundException("Política no encontrada con id: " + unknownId));

        mockMvc.perform(get("/api/v1/policies/{id}", unknownId))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.errorCode").value("NOT_FOUND"));
    }
}
