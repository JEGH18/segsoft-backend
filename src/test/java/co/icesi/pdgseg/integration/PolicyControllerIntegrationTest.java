package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
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

import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
class PolicyControllerIntegrationTest extends PostgreSQLContainerBase {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanPolicies() {
        jdbcTemplate.execute("DELETE FROM policy_audit_log");
        jdbcTemplate.execute("DELETE FROM policies");
    }

    private String body(String name, String desc, Category cat, Framework fw, String controlId)
            throws Exception {
        return objectMapper.writeValueAsString(Map.of(
            "name", name,
            "description", desc,
            "category", cat.name(),
            "framework", fw.name(),
            "controlId", controlId != null ? controlId : ""
        ));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_asAdmin_returns201() throws Exception {
        String json = body(
            "Política SQL integración",
            "Previene inyecciones SQL mediante el uso obligatorio de queries parametrizadas.",
            Category.SQL_INJECTION,
            Framework.OWASP_TOP_10_2021,
            "A03:2021"
        );

        mockMvc.perform(post("/api/v1/policies")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").isNotEmpty())
            .andExpect(jsonPath("$.name").value("Política SQL integración"))
            .andExpect(jsonPath("$.status").value("ACTIVE"))
            .andExpect(jsonPath("$.version").value(1))
            .andExpect(jsonPath("$.category").value("SQL_INJECTION"))
            .andExpect(jsonPath("$.framework").value("OWASP_TOP_10_2021"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void createPolicy_asDeveloper_returns403() throws Exception {
        String json = body(
            "Política no permitida",
            "Esta política no debería crearse con rol developer.",
            Category.XSS,
            Framework.ISO_27001,
            null
        );

        mockMvc.perform(post("/api/v1/policies")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isForbidden());
    }

    @Test
    void createPolicy_withoutToken_returns401or403() throws Exception {
        String json = body(
            "Política sin auth",
            "Esta política no debería crearse sin autenticación.",
            Category.XSS,
            Framework.ISO_27001,
            null
        );

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
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.errors.description").exists());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_duplicate_returns409() throws Exception {
        String json = body(
            "Política duplicada única",
            "Esta política no debería poder crearse dos veces con el mismo framework.",
            Category.AUTHENTICATION_FAILURE,
            Framework.OWASP_ASVS,
            null
        );

        mockMvc.perform(post("/api/v1/policies")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isCreated());

        mockMvc.perform(post("/api/v1/policies")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.errorCode").value("POLICY_CONFLICT"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_invalidEnumValue_returns400() throws Exception {
        String json = "{\"name\":\"Bad enum\",\"description\":\"Descripción suficientemente larga para pasar validación.\","
            + "\"category\":\"INVALID_CATEGORY\",\"framework\":\"ISO_27001\"}";

        mockMvc.perform(post("/api/v1/policies")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void createPolicy_allFiveCategories_eachCreatedSuccessfully() throws Exception {
        for (Category cat : Category.values()) {
            String json = body(
                "Política cobertura " + cat.name(),
                "Descripción con la longitud mínima requerida de veinte caracteres para " + cat.name(),
                cat,
                Framework.OWASP_TOP_10_2021,
                null
            );

            mockMvc.perform(post("/api/v1/policies")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.category").value(cat.name()));
        }
    }
}
