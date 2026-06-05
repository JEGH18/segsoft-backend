package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.config.WebMvcConfig;
import co.icesi.pdgseg.dto.response.RuleResponse;
import co.icesi.pdgseg.entity.enums.RuleStatus;
import co.icesi.pdgseg.entity.enums.RuleType;
import co.icesi.pdgseg.entity.enums.Severity;
import co.icesi.pdgseg.exception.InvalidRulePayloadException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.filter.RateLimitInterceptor;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.RuleService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(RuleController.class)
@Import({SecurityConfig.class, WebMvcConfig.class, RateLimitInterceptor.class})
class RuleControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockBean RuleService ruleService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean UserDetailsServiceImpl userDetailsService;

    private RuleResponse stub(UUID policyId) {
        return new RuleResponse(
            UUID.randomUUID(), policyId,
            RuleType.PATTERN_REGEX,
            Map.of("pattern", "(?i)password\\s*="),
            null, List.of("java"), Severity.HIGH, "CWE-798",
            "INSECURE_DATA_HANDLING", RuleStatus.ACTIVE, OffsetDateTime.now()
        );
    }

    private Map<String, Object> validBody(String pattern) {
        return Map.of(
            "type", "PATTERN_REGEX",
            "payload", Map.of("pattern", pattern),
            "languages", List.of("java"),
            "severity", "HIGH"
        );
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createRule_asAdmin_returns201() throws Exception {
        UUID policyId = UUID.randomUUID();
        when(ruleService.create(eq(policyId), any())).thenReturn(stub(policyId));

        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validBody("(?i)password\\s*="))))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.type").value("PATTERN_REGEX"))
            .andExpect(jsonPath("$.status").value("ACTIVE"))
            .andExpect(jsonPath("$.severity").value("HIGH"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void createRule_asDeveloper_returns403() throws Exception {
        UUID policyId = UUID.randomUUID();
        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validBody("test"))))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createRule_invalidRegex_returns400() throws Exception {
        UUID policyId = UUID.randomUUID();
        when(ruleService.create(eq(policyId), any()))
            .thenThrow(new InvalidRulePayloadException("Patrón regex inválido en posición 0: ..."));

        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validBody("[invalid"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errorCode").value("INVALID_RULE_PAYLOAD"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createRule_nonExistentPolicy_returns404() throws Exception {
        UUID policyId = UUID.randomUUID();
        when(ruleService.create(eq(policyId), any()))
            .thenThrow(new ResourceNotFoundException("Política no encontrada"));

        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validBody("test"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.errorCode").value("NOT_FOUND"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void listRules_authenticated_returns200() throws Exception {
        UUID policyId = UUID.randomUUID();
        when(ruleService.listByPolicy(eq(policyId), any()))
            .thenReturn(new PageImpl<>(List.of(stub(policyId)), PageRequest.of(0, 20), 1));

        mockMvc.perform(get("/api/v1/policies/{id}/rules", policyId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].type").value("PATTERN_REGEX"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void archiveRule_asAdmin_returns200() throws Exception {
        UUID ruleId = UUID.randomUUID();
        RuleResponse archived = new RuleResponse(
            ruleId, UUID.randomUUID(), RuleType.PATTERN_REGEX,
            Map.of("pattern", "test"), null, List.of(),
            Severity.LOW, null, null, RuleStatus.ARCHIVED, OffsetDateTime.now()
        );
        when(ruleService.archive(ruleId)).thenReturn(archived);

        mockMvc.perform(delete("/api/v1/rules/{id}", ruleId).with(csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("ARCHIVED"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = "AUDITOR")
    void archiveRule_asAuditor_returns403() throws Exception {
        mockMvc.perform(delete("/api/v1/rules/{id}", UUID.randomUUID()).with(csrf()))
            .andExpect(status().isForbidden());
    }
}
