package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "jwt.secret=integration-test-secret-minimum-32-characters-ok",
        "jwt.access-token-expiration-ms=900000",
        "jwt.refresh-token-expiration-ms=28800000",
        "cors.allowed-origins=http://localhost:5173"
    }
)
@AutoConfigureMockMvc
class RuleControllerIntegrationTest extends PostgreSQLContainerBase {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired JdbcTemplate jdbcTemplate;

    private UUID policyId;

    @BeforeEach
    void setup() {
        jdbcTemplate.execute("DELETE FROM rules");
        jdbcTemplate.execute("DELETE FROM policy_audit_log");
        jdbcTemplate.execute("DELETE FROM policies");

        policyId = jdbcTemplate.queryForObject(
            "INSERT INTO policies (name, description, category, framework, status, version, weight, created_at) " +
            "VALUES ('Política Integración', 'Descripción de prueba suficientemente larga', " +
            "'SQL_INJECTION', 'OWASP_TOP_10_2021', 'ACTIVE', 1, 50, now()) RETURNING id",
            UUID.class
        );
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createRule_validRegex_returns201() throws Exception {
        Map<String, Object> body = Map.of(
            "type", "PATTERN_REGEX",
            "payload", Map.of("pattern", "(?i)(api[_-]?key)\\s*="),
            "languages", List.of("java", "python"),
            "severity", "HIGH",
            "cweId", "CWE-798"
        );

        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").isNotEmpty())
            .andExpect(jsonPath("$.type").value("PATTERN_REGEX"))
            .andExpect(jsonPath("$.severity").value("HIGH"))
            .andExpect(jsonPath("$.status").value("ACTIVE"))
            .andExpect(jsonPath("$.policyId").value(policyId.toString()));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createRule_invalidRegex_returns400WithPosition() throws Exception {
        Map<String, Object> body = Map.of(
            "type", "PATTERN_REGEX",
            "payload", Map.of("pattern", "[invalid(regex"),
            "severity", "LOW"
        );

        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errorCode").value("INVALID_RULE_PAYLOAD"))
            .andExpect(jsonPath("$.message").value(containsString("posición")));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void archiveRule_returns200WithArchivedStatus() throws Exception {
        // Create first
        Map<String, Object> body = Map.of(
            "type", "PATTERN_REGEX",
            "payload", Map.of("pattern", "secret\\s*="),
            "severity", "HIGH"
        );
        String response = mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();

        String ruleId = objectMapper.readTree(response).get("id").asText();

        // Archive
        mockMvc.perform(delete("/api/v1/rules/{id}", ruleId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("ARCHIVED"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void getById_policyWithRule_showsExecutableTrue() throws Exception {
        // Create a rule
        Map<String, Object> ruleBody = Map.of(
            "type", "PATTERN_REGEX",
            "payload", Map.of("pattern", "test"),
            "severity", "LOW"
        );
        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(ruleBody)))
            .andExpect(status().isCreated());

        // Check policy detail
        mockMvc.perform(get("/api/v1/policies/{id}", policyId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.executable").value(true))
            .andExpect(jsonPath("$.rulesCount").value(1));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void createRule_asDeveloper_returns403() throws Exception {
        Map<String, Object> body = Map.of(
            "type", "PATTERN_REGEX",
            "payload", Map.of("pattern", "test"),
            "severity", "LOW"
        );
        mockMvc.perform(post("/api/v1/policies/{id}/rules", policyId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void getCoverage_returns5Categories() throws Exception {
        mockMvc.perform(get("/api/v1/policies/coverage"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(5)))
            .andExpect(jsonPath("$[*].category", hasItems(
                "SQL_INJECTION", "XSS", "AUTHENTICATION_FAILURE",
                "INSECURE_DATA_HANDLING", "DEPENDENCY_VULNERABILITY"
            )));
    }
}
