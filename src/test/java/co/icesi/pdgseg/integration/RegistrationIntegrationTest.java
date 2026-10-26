package co.icesi.pdgseg.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Self-registration end to end against PostgreSQL: the new account is a DEVELOPER with a working
 * session, and the endpoint enforces uniqueness, the username format and the password policy.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "cors.allowed-origins=http://localhost:5173",
                "auth.registration.enabled=true"
        }
)
@AutoConfigureMockMvc
class RegistrationIntegrationTest extends PostgreSQLContainerBase {

    private static final String PASSWORD = "Registro-Prueba-2026!";
    // Unique per run: the integration database may be reused between local runs.
    private static final String RUN = Long.toString(System.nanoTime(), 36);
    private static final AtomicInteger SEQ = new AtomicInteger();

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;

    private static String newUsername() {
        return "reg" + RUN + "x" + SEQ.incrementAndGet();
    }

    private ResultActions register(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", password))));
    }

    private ResultActions login(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", password))));
    }

    @Test
    void register_createsADeveloperAccountWithAWorkingSession() throws Exception {
        String username = newUsername();

        MvcResult result = register(username.toUpperCase(), PASSWORD)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.roles.length()").value(1))
                .andExpect(jsonPath("$.roles[0]").value("DEVELOPER"))
                .andExpect(cookie().exists("refresh_token"))
                .andExpect(cookie().httpOnly("refresh_token", true))
                .andReturn();

        // Stored in lowercase, enabled, with DEVELOPER as its only role.
        List<String> roles = jdbcTemplate.queryForList("""
                SELECT r.name FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id
                WHERE u.username = ? AND u.enabled
                """, String.class, username);
        assertThat(roles).containsExactly("DEVELOPER");

        String token = objectMapper.readTree(result.getResponse().getContentAsString()).get("accessToken").asText();
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.roles.length()").value(1))
                .andExpect(jsonPath("$.roles[0]").value("DEVELOPER"));

        // A DEVELOPER cannot see compliance reports.
        mockMvc.perform(get("/api/v1/reports").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());

        // The refresh cookie restores the session.
        Cookie refresh = result.getResponse().getCookie("refresh_token");
        mockMvc.perform(post("/api/v1/auth/refresh").cookie(refresh))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());

        login(username, PASSWORD).andExpect(status().isOk());
        Integer audited = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM auth_audit_log WHERE event_type = 'USER_REGISTERED' AND username = ?",
                Integer.class, username);
        assertThat(audited).isEqualTo(1);
    }

    @Test
    void register_rejectsAUsernameThatAlreadyExistsInAnotherCase() throws Exception {
        String username = newUsername();
        register(username, PASSWORD).andExpect(status().isCreated());

        register(username.toUpperCase(), PASSWORD)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Ese nombre de usuario ya está en uso"));
    }

    @Test
    void register_rejectsAWeakPasswordWithTheReason() throws Exception {
        register(newUsername(), "solominusculas123")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.errors.password").value("La contraseña debe contener al menos una letra mayúscula"));
    }

    @Test
    void register_rejectsAnInvalidUsername() throws Exception {
        register("1no-empieza-por-letra", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.username").exists());
        register("con espacios", PASSWORD)
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_rejectsReservedUsernames() throws Exception {
        register("Admin", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Ese nombre de usuario está reservado. Elige otro."));
    }

    @Test
    void registrationStatus_isPublic() throws Exception {
        mockMvc.perform(get("/api/v1/auth/registration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    void login_rejectsADisabledAccount() throws Exception {
        String username = newUsername();
        register(username, PASSWORD).andExpect(status().isCreated());
        jdbcTemplate.update("UPDATE users SET enabled = false WHERE username = ?", username);

        login(username, PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Credenciales inválidas"));
    }
}
