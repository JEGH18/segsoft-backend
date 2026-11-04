package co.icesi.pdgseg.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Brute-force protection against PostgreSQL: a failed login is rejected with an exception, and
 * what the login stored before throwing (the failed attempts, the lock, the audit) must survive it.
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
class LoginLockoutIntegrationTest extends PostgreSQLContainerBase {

    private static final String PASSWORD = "Bloqueo-Prueba-2026!";
    private static final String WRONG_PASSWORD = "Clave-Incorrecta-2026!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private PasswordEncoder passwordEncoder;

    /** A DEVELOPER without email, like the deployment accounts, unique per run. */
    private String newAccount() {
        String username = "lock" + Long.toString(System.nanoTime(), 36);
        jdbcTemplate.update("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                username, passwordEncoder.encode(PASSWORD));
        jdbcTemplate.update("""
                INSERT INTO user_roles (user_id, role_id)
                SELECT u.id, r.id FROM users u, roles r WHERE u.username = ? AND r.name = 'DEVELOPER'
                """, username);
        return username;
    }

    private ResultActions login(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", password))));
    }

    private int failedAttempts(String username) {
        return jdbcTemplate.queryForObject("SELECT failed_attempts FROM users WHERE username = ?",
                Integer.class, username);
    }

    private int audited(String username, String eventType) {
        return jdbcTemplate.queryForObject(
                "SELECT count(*) FROM auth_audit_log WHERE username = ? AND event_type = ?",
                Integer.class, username, eventType);
    }

    @Test
    void eachWrongPasswordIsCountedAndAudited() throws Exception {
        String username = newAccount();

        login(username, WRONG_PASSWORD).andExpect(status().isUnauthorized());
        login(username, WRONG_PASSWORD).andExpect(status().isUnauthorized());

        assertThat(failedAttempts(username)).isEqualTo(2);
        assertThat(audited(username, "LOGIN_FAILURE")).isEqualTo(2);
    }

    @Test
    void fiveWrongPasswordsLockTheAccount_evenForTheRightPassword() throws Exception {
        String username = newAccount();

        for (int i = 0; i < 5; i++) {
            login(username, WRONG_PASSWORD).andExpect(status().isUnauthorized());
        }

        Boolean locked = jdbcTemplate.queryForObject(
                "SELECT locked_until > now() + interval '25 minutes' FROM users WHERE username = ?",
                Boolean.class, username);
        assertThat(locked).isTrue();

        // Same answer as a wrong password, so the lock does not reveal that the account exists.
        login(username, PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Credenciales inválidas"));
        assertThat(audited(username, "ACCOUNT_LOCKED")).isEqualTo(1);
    }

    @Test
    void aSuccessfulLoginResetsTheCounter() throws Exception {
        String username = newAccount();
        login(username, WRONG_PASSWORD).andExpect(status().isUnauthorized());
        assertThat(failedAttempts(username)).isEqualTo(1);

        login(username, PASSWORD).andExpect(status().isOk());

        assertThat(failedAttempts(username)).isZero();
        assertThat(audited(username, "LOGIN_SUCCESS")).isEqualTo(1);
    }

    @Test
    void anUnknownUserIsAudited() throws Exception {
        String username = "nadie" + Long.toString(System.nanoTime(), 36);

        login(username, WRONG_PASSWORD).andExpect(status().isUnauthorized());

        assertThat(audited(username, "LOGIN_FAILURE")).isEqualTo(1);
    }
}
