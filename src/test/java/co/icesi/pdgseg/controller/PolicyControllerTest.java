package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.exception.PolicyConflictException;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.PolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(PolicyController.class)
@Import(SecurityConfig.class)
class PolicyControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockBean PolicyService policyService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean UserDetailsServiceImpl userDetailsService;

    private PolicyResponse stubResponse(String name) {
        return new PolicyResponse(
            UUID.randomUUID(), name,
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.SQL_INJECTION, Framework.OWASP_TOP_10_2021, "A03:2021",
            PolicyStatus.ACTIVE, 1, 50, OffsetDateTime.now(), UUID.randomUUID(), false, 0
        );
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_asAdmin_returns201() throws Exception {
        when(policyService.create(any(), eq("admin"))).thenReturn(stubResponse("Política SQL test"));

        String json = objectMapper.writeValueAsString(Map.of(
            "name", "Política SQL test",
            "description", "Previene inyecciones SQL mediante queries parametrizadas en todas las capas.",
            "category", "SQL_INJECTION",
            "framework", "OWASP_TOP_10_2021",
            "controlId", "A03:2021"
        ));

        mockMvc.perform(post("/api/v1/policies")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.name").value("Política SQL test"))
            .andExpect(jsonPath("$.status").value("ACTIVE"))
            .andExpect(jsonPath("$.version").value(1))
            .andExpect(jsonPath("$.category").value("SQL_INJECTION"))
            .andExpect(jsonPath("$.framework").value("OWASP_TOP_10_2021"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void createPolicy_asDeveloper_returns403() throws Exception {
        String json = objectMapper.writeValueAsString(Map.of(
            "name", "Política no permitida",
            "description", "Esta política no debería crearse con rol developer.",
            "category", "XSS",
            "framework", "ISO_27001"
        ));

        mockMvc.perform(post("/api/v1/policies")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isForbidden());
    }

    @Test
    void createPolicy_withoutToken_returns401or403() throws Exception {
        String json = objectMapper.writeValueAsString(Map.of(
            "name", "Sin auth",
            "description", "Sin autenticación.",
            "category", "XSS",
            "framework", "ISO_27001"
        ));

        mockMvc.perform(post("/api/v1/policies")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().is(anyOf(is(401), is(403))));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_missingFramework_returns400() throws Exception {
        String json = objectMapper.writeValueAsString(Map.of(
            "name", "Política sin framework",
            "description", "Descripción con la longitud mínima requerida de veinte caracteres.",
            "category", "SQL_INJECTION"
        ));

        mockMvc.perform(post("/api/v1/policies")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errors.framework").exists());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_descriptionTooShort_returns400() throws Exception {
        String json = objectMapper.writeValueAsString(Map.of(
            "name", "Política corta",
            "description", "Corta",
            "category", "XSS",
            "framework", "ISO_27001"
        ));

        mockMvc.perform(post("/api/v1/policies")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errors.description").exists());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_duplicate_returns409() throws Exception {
        when(policyService.create(any(), any()))
            .thenThrow(new PolicyConflictException("Ya existe una política duplicada"));

        String json = objectMapper.writeValueAsString(Map.of(
            "name", "Política duplicada",
            "description", "Esta política no debería poder crearse dos veces con el mismo framework.",
            "category", "AUTHENTICATION_FAILURE",
            "framework", "OWASP_ASVS"
        ));

        mockMvc.perform(post("/api/v1/policies")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.errorCode").value("POLICY_CONFLICT"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_invalidEnumValue_returns400() throws Exception {
        String json = "{\"name\":\"Bad enum\","
            + "\"description\":\"Descripción suficientemente larga para pasar la validación de longitud.\","
            + "\"category\":\"INVALID_CATEGORY\",\"framework\":\"ISO_27001\"}";

        mockMvc.perform(post("/api/v1/policies")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_allFiveCategories_eachMapped() throws Exception {
        for (Category cat : Category.values()) {
            when(policyService.create(any(), eq("admin"))).thenReturn(stubResponse("Política " + cat));

            String json = objectMapper.writeValueAsString(Map.of(
                "name", "Política cobertura " + cat.name(),
                "description", "Descripción con la longitud mínima requerida de veinte caracteres.",
                "category", cat.name(),
                "framework", "OWASP_TOP_10_2021"
            ));

            mockMvc.perform(post("/api/v1/policies")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json))
                .andExpect(status().isCreated());
        }
    }
}
