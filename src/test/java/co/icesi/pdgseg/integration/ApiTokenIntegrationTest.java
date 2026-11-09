package co.icesi.pdgseg.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.Timestamp;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * A DEVELOPER creates an API token with their web session, a pipeline uses it, and revoking it
 * locks the pipeline out: against a real PostgreSQL, so V37 and the entity mapping are exercised.
 */
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
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiTokenIntegrationTest extends PostgreSQLContainerBase {

    private static final String USERNAME = "ci.developer";
    private static final String PASSWORD = "Ci-Developer-2026!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private PasswordEncoder passwordEncoder;

    @BeforeAll
    void seedDeveloper() {
        jdbcTemplate.update(
            "INSERT INTO users (username, password_hash) VALUES (?, ?) " +
            "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, enabled = true, locked_until = NULL",
            USERNAME, passwordEncoder.encode(PASSWORD));
        jdbcTemplate.update(
            "INSERT INTO user_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r " +
            "WHERE u.username = ? AND r.name = 'DEVELOPER' ON CONFLICT DO NOTHING", USERNAME);
        jdbcTemplate.update("DELETE FROM api_tokens WHERE created_by = (SELECT id FROM users WHERE username = ?)", USERNAME);
    }

    private String sessionToken() throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("username", USERNAME, "password", PASSWORD))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).path("accessToken").asText();
    }

    private JsonNode createToken(String session, String name) throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/api-tokens")
                        .header("Authorization", "Bearer " + session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("name", name, "expiresInDays", 30))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body);
    }

    @Test
    void aDeveloperCreatesUsesAndRevokesAnApiToken() throws Exception {
        String session = sessionToken();
        JsonNode created = createToken(session, "GitHub Actions");
        String apiToken = created.path("token").asText();
        assertThat(apiToken).startsWith("pdgseg_");

        // Only the hash is stored.
        String storedHash = jdbcTemplate.queryForObject(
            "SELECT token_hash FROM api_tokens WHERE id = ?::uuid", String.class, created.path("id").asText());
        assertThat(storedHash).hasSize(64).doesNotContain(apiToken);

        // The pipeline authenticates as the developer, with the developer's role.
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + apiToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(USERNAME));
        mockMvc.perform(get("/api/v1/policy-sets").header("Authorization", "Bearer " + apiToken))
                .andExpect(status().isOk());
        Timestamp lastUsed = jdbcTemplate.queryForObject(
            "SELECT last_used_at FROM api_tokens WHERE id = ?::uuid", Timestamp.class, created.path("id").asText());
        assertThat(lastUsed).isNotNull();

        // It cannot manage tokens.
        mockMvc.perform(get("/api/v1/auth/api-tokens").header("Authorization", "Bearer " + apiToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("API_TOKEN_NOT_ALLOWED"));

        // The developer lists it (metadata only) and revokes it.
        mockMvc.perform(get("/api/v1/auth/api-tokens").header("Authorization", "Bearer " + session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("GitHub Actions"))
                .andExpect(jsonPath("$[0].ownerUsername").value(USERNAME))
                .andExpect(jsonPath("$[0].tokenPrefix").value(apiToken.substring(0, 12)))
                .andExpect(jsonPath("$[0].token").doesNotExist());
        mockMvc.perform(delete("/api/v1/auth/api-tokens/{id}", created.path("id").asText())
                        .header("Authorization", "Bearer " + session))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + apiToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_API_TOKEN"));
    }

    @Test
    void anExpiredTokenNoLongerAuthenticates() throws Exception {
        JsonNode created = createToken(sessionToken(), "vencido");
        jdbcTemplate.update("UPDATE api_tokens SET expires_at = now() - interval '1 minute' WHERE id = ?::uuid",
            created.path("id").asText());

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + created.path("token").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_API_TOKEN"));
    }

    @Test
    void aTokenOfADisabledAccountNoLongerAuthenticates() throws Exception {
        JsonNode created = createToken(sessionToken(), "cuenta deshabilitada");
        jdbcTemplate.update("UPDATE users SET enabled = false WHERE username = ?", USERNAME);
        try {
            mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + created.path("token").asText()))
                    .andExpect(status().isUnauthorized());
        } finally {
            jdbcTemplate.update("UPDATE users SET enabled = true WHERE username = ?", USERNAME);
        }
    }
}
