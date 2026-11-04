package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.service.EmailVerificationService;
import co.icesi.pdgseg.service.VerificationEmailRequested;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Self-registration end to end against PostgreSQL: the new account is a DEVELOPER that can only
 * log in after verifying its email, and the endpoints enforce uniqueness of the username and the
 * email, their format and the password policy. The raw verification token is taken from the
 * published {@link VerificationEmailRequested} event, as the email would carry it.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "cors.allowed-origins=http://localhost:5173",
                "auth.registration.enabled=true",
                // Every request of the suite comes from the same IP.
                "auth.registration.max-per-ip-per-hour=1000",
                // No SMTP in the tests: the link goes to the log and the token comes from the event.
                "auth.email-verification.log-links=true"
        }
)
@AutoConfigureMockMvc
@RecordApplicationEvents
class RegistrationIntegrationTest extends PostgreSQLContainerBase {

    private static final String PASSWORD = "Registro-Prueba-2026!";
    // Unique per run: the integration database may be reused between local runs.
    private static final String RUN = Long.toString(System.nanoTime(), 36);
    private static final AtomicInteger SEQ = new AtomicInteger();

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private ApplicationEvents events;
    @Autowired private EmailVerificationService emailVerificationService;

    private static String newUsername() {
        return "reg" + RUN + "x" + SEQ.incrementAndGet();
    }

    private static String emailOf(String username) {
        return username.toLowerCase() + "@example.com";
    }

    private ResultActions postJson(String path, Map<String, String> body) throws Exception {
        return mockMvc.perform(post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)));
    }

    private ResultActions register(String username, String email, String password) throws Exception {
        return postJson("/api/v1/auth/register", Map.of("username", username, "email", email, "password", password));
    }

    private ResultActions register(String username) throws Exception {
        return register(username, emailOf(username), PASSWORD);
    }

    private ResultActions login(String username, String password) throws Exception {
        return postJson("/api/v1/auth/login", Map.of("username", username, "password", password));
    }

    private ResultActions verify(String token) throws Exception {
        return postJson("/api/v1/auth/verify-email", Map.of("token", token));
    }

    /** The token of the last verification email sent to {@code username}. */
    private String lastToken(String username) {
        List<VerificationEmailRequested> sent = events.stream(VerificationEmailRequested.class)
                .filter(event -> event.username().equals(username))
                .toList();
        assertThat(sent).as("correos de verificación de %s", username).isNotEmpty();
        return sent.get(sent.size() - 1).token();
    }

    /** Registers and verifies a new account. */
    private String verifiedUsername() throws Exception {
        String username = newUsername();
        register(username).andExpect(status().isCreated());
        verify(lastToken(username)).andExpect(status().isOk());
        return username;
    }

    @Test
    void register_createsAnUnverifiedDeveloper_thatLogsInOnlyAfterVerifyingItsEmail() throws Exception {
        String username = newUsername();

        register(username.toUpperCase(), "  " + emailOf(username).toUpperCase() + " ", PASSWORD)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(emailOf(username)))
                .andExpect(jsonPath("$.message").isNotEmpty())
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(cookie().doesNotExist("refresh_token"));

        // Stored in lowercase, enabled, unverified, with DEVELOPER as its only role.
        Map<String, Object> row = jdbcTemplate.queryForMap(
                "SELECT email, email_verified_at FROM users WHERE username = ? AND enabled", username);
        assertThat(row.get("email")).isEqualTo(emailOf(username));
        assertThat(row.get("email_verified_at")).isNull();
        List<String> roles = jdbcTemplate.queryForList("""
                SELECT r.name FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id
                WHERE u.username = ?
                """, String.class, username);
        assertThat(roles).containsExactly("DEVELOPER");

        // Only the hash of the emailed token is stored.
        String token = lastToken(username);
        List<String> hashes = jdbcTemplate.queryForList("""
                SELECT t.token_hash FROM email_verification_tokens t JOIN users u ON u.id = t.user_id
                WHERE u.username = ?
                """, String.class, username);
        assertThat(hashes).hasSize(1).doesNotContain(token);

        // Without verifying, the right password gets a specific answer and a wrong one the usual 401.
        login(username, PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("EMAIL_NOT_VERIFIED"))
                .andExpect(jsonPath("$.email").value(emailOf(username)));
        login(username, "Otra-Clave-Incorrecta-1!")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.email").doesNotExist());

        // The link verifies the email and starts the session.
        MvcResult verified = verify(token)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.roles[0]").value("DEVELOPER"))
                .andExpect(cookie().exists("refresh_token"))
                .andExpect(cookie().httpOnly("refresh_token", true))
                .andReturn();
        assertThat(jdbcTemplate.queryForObject(
                "SELECT email_verified_at IS NOT NULL FROM users WHERE username = ?", Boolean.class, username))
                .isTrue();

        String accessToken = objectMapper.readTree(verified.getResponse().getContentAsString())
                .get("accessToken").asText();
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(emailOf(username)))
                .andExpect(jsonPath("$.roles.length()").value(1))
                .andExpect(jsonPath("$.roles[0]").value("DEVELOPER"));

        // A DEVELOPER cannot see compliance reports.
        mockMvc.perform(get("/api/v1/reports").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());

        // The refresh cookie restores the session.
        Cookie refresh = verified.getResponse().getCookie("refresh_token");
        mockMvc.perform(post("/api/v1/auth/refresh").cookie(refresh))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());

        login(username, PASSWORD).andExpect(status().isOk());

        // The link works only once.
        verify(token)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_VERIFICATION_TOKEN"))
                .andExpect(jsonPath("$.message").value("Tu correo ya está verificado. Inicia sesión."));

        Integer audited = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM auth_audit_log WHERE event_type IN ('USER_REGISTERED', 'EMAIL_VERIFIED') "
                        + "AND username = ?", Integer.class, username);
        assertThat(audited).isEqualTo(2);
    }

    @Test
    void register_rejectsAUsernameThatAlreadyExistsInAnotherCase() throws Exception {
        String username = newUsername();
        register(username).andExpect(status().isCreated());

        register(username.toUpperCase(), "otro" + emailOf(username), PASSWORD)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Ese nombre de usuario ya está en uso"));
    }

    @Test
    void register_rejectsAnEmailThatAnotherAccountUses_inAnotherCase() throws Exception {
        String username = newUsername();
        register(username).andExpect(status().isCreated());

        register(newUsername(), emailOf(username).toUpperCase(), PASSWORD)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("CONFLICT"))
                .andExpect(jsonPath("$.message").value("Ese correo ya está registrado en otra cuenta"));
    }

    @Test
    void theDatabaseKeepsEmailsUniqueIgnoringCase() throws Exception {
        String first = newUsername();
        String second = newUsername();
        register(first).andExpect(status().isCreated());
        register(second).andExpect(status().isCreated());

        // Covers two registrations that pass the service check at the same time.
        assertThatThrownBy(() -> jdbcTemplate.update("UPDATE users SET email = ? WHERE username = ?",
                emailOf(first).toUpperCase(), second))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void register_rejectsAMissingOrInvalidEmail() throws Exception {
        register(newUsername(), "no-es-un-correo", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").value("El correo no es válido"));
        postJson("/api/v1/auth/register", Map.of("username", newUsername(), "password", PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").value("El correo es requerido"));
    }

    @Test
    void register_rejectsAWeakPasswordWithTheReason() throws Exception {
        String username = newUsername();
        register(username, emailOf(username), "solominusculas123")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.errors.password").value("La contraseña debe contener al menos una letra mayúscula"));
    }

    @Test
    void register_rejectsAnInvalidUsername() throws Exception {
        register("1no-empieza-por-letra", "a@example.com", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.username").exists());
        register("con espacios", "b@example.com", PASSWORD)
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_rejectsReservedUsernames() throws Exception {
        register("Admin", "admin" + RUN + "@example.com", PASSWORD)
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
    void resend_replacesTheLink_andAnswersTheSameForUnknownEmails() throws Exception {
        String username = newUsername();
        register(username).andExpect(status().isCreated());
        String first = lastToken(username);

        // Within the cooldown no new link is issued.
        postJson("/api/v1/auth/resend-verification", Map.of("email", emailOf(username)))
                .andExpect(status().isAccepted());
        assertThat(lastToken(username)).isEqualTo(first);

        jdbcTemplate.update("""
                UPDATE email_verification_tokens SET created_at = now() - interval '2 minutes'
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                """, username);
        postJson("/api/v1/auth/resend-verification", Map.of("email", emailOf(username).toUpperCase()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").isNotEmpty());
        String second = lastToken(username);
        assertThat(second).isNotEqualTo(first);

        verify(first).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_VERIFICATION_TOKEN"));
        verify(second).andExpect(status().isOk());

        postJson("/api/v1/auth/resend-verification", Map.of("email", "nadie-" + RUN + "@example.com"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").isNotEmpty());
    }

    @Test
    void verify_rejectsAnExpiredOrUnknownLink() throws Exception {
        String username = newUsername();
        register(username).andExpect(status().isCreated());
        jdbcTemplate.update("""
                UPDATE email_verification_tokens SET expires_at = now() - interval '1 minute'
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                """, username);

        verify(lastToken(username))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_VERIFICATION_TOKEN"));
        verify("token-inventado")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_VERIFICATION_TOKEN"));
        login(username, PASSWORD).andExpect(status().isForbidden());
    }

    @Test
    void accountsWithoutEmail_keepLoggingIn() throws Exception {
        // Accounts registered before V34 have no email and are not asked to verify one.
        String username = newUsername();
        register(username).andExpect(status().isCreated());
        jdbcTemplate.update("UPDATE users SET email = NULL WHERE username = ?", username);

        login(username, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void unverifiedAccountsArePurged_freeingTheirNameAndEmail() throws Exception {
        String username = newUsername();
        register(username).andExpect(status().isCreated());
        jdbcTemplate.update("UPDATE users SET created_at = now() - interval '8 days' WHERE username = ?", username);
        String verified = verifiedUsername();
        jdbcTemplate.update("UPDATE users SET created_at = now() - interval '8 days' WHERE username = ?", verified);

        emailVerificationService.purgeExpired();

        assertThat(jdbcTemplate.queryForObject(
                "SELECT count(*) FROM users WHERE username = ?", Integer.class, username)).isZero();
        assertThat(jdbcTemplate.queryForObject(
                "SELECT count(*) FROM users WHERE username = ?", Integer.class, verified)).isEqualTo(1);
        register(username).andExpect(status().isCreated());
    }

    @Test
    void login_rejectsADisabledAccount() throws Exception {
        String username = verifiedUsername();
        jdbcTemplate.update("UPDATE users SET enabled = false WHERE username = ?", username);

        login(username, PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.startsWith("Credenciales inválidas")));
    }
}
