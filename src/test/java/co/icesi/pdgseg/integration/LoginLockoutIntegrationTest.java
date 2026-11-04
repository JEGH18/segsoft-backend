package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.service.AccountUnlockRequested;
import co.icesi.pdgseg.service.VerificationEmailRequested;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Brute-force protection against PostgreSQL: each failed login warns how many attempts are left,
 * the fifth locks the account for 30 minutes and emails an unlock link to its verified email, and
 * what the login stored before rejecting (attempts, lock, link, audit) survives the rejection.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "cors.allowed-origins=http://localhost:5173",
                // No SMTP in the tests: the link goes to the log and the token comes from the event.
                "auth.email-verification.log-links=true"
        }
)
@AutoConfigureMockMvc
@RecordApplicationEvents
class LoginLockoutIntegrationTest extends PostgreSQLContainerBase {

    private static final String PASSWORD = "Bloqueo-Prueba-2026!";
    private static final String WRONG_PASSWORD = "Clave-Incorrecta-2026!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private ApplicationEvents events;

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

    /** A DEVELOPER with a verified email, like a self-registered account. */
    private String newAccountWithVerifiedEmail() {
        String username = newAccount();
        jdbcTemplate.update("UPDATE users SET email = ?, email_verified_at = now() WHERE username = ?",
                username + "@example.com", username);
        return username;
    }

    private ResultActions postJson(String path, Map<String, String> body) throws Exception {
        return mockMvc.perform(post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)));
    }

    private ResultActions login(String username, String password) throws Exception {
        return postJson("/api/v1/auth/login", Map.of("username", username, "password", password));
    }

    private void failFourTimes(String username) throws Exception {
        for (int i = 0; i < 4; i++) {
            login(username, WRONG_PASSWORD).andExpect(status().isUnauthorized());
        }
    }

    private int failedAttempts(String username) {
        return jdbcTemplate.queryForObject("SELECT failed_attempts FROM users WHERE username = ?",
                Integer.class, username);
    }

    private boolean locked(String username) {
        return jdbcTemplate.queryForObject(
                "SELECT locked_until IS NOT NULL AND locked_until > now() FROM users WHERE username = ?",
                Boolean.class, username);
    }

    private int audited(String username, String eventType) {
        return jdbcTemplate.queryForObject(
                "SELECT count(*) FROM auth_audit_log WHERE username = ? AND event_type = ?",
                Integer.class, username, eventType);
    }

    private List<AccountUnlockRequested> unlockEmails(String username) {
        return events.stream(AccountUnlockRequested.class)
                .filter(event -> event.username().equals(username))
                .toList();
    }

    @Test
    void eachWrongPasswordIsCounted_audited_andSaysHowManyAttemptsAreLeft() throws Exception {
        String username = newAccount();

        login(username, WRONG_PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.attemptsLeft").value(4))
                .andExpect(jsonPath("$.message").value(
                        "Credenciales inválidas. Te quedan 4 intentos antes de que la cuenta se bloquee durante 30 minutos."));
        login(username, WRONG_PASSWORD).andExpect(jsonPath("$.attemptsLeft").value(3));

        assertThat(failedAttempts(username)).isEqualTo(2);
        assertThat(audited(username, "LOGIN_FAILURE")).isEqualTo(2);
    }

    @Test
    void theFifthWrongPasswordLocksTheAccount_andEmailsAnUnlockLinkThatLiftsIt() throws Exception {
        String username = newAccountWithVerifiedEmail();
        failFourTimes(username);

        login(username, WRONG_PASSWORD)
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.errorCode").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.minutesLeft").value(30))
                .andExpect(jsonPath("$.message").value("Demasiados intentos fallidos: la cuenta quedó bloqueada "
                        + "durante 30 minutos. Te enviamos un correo con un enlace para desbloquearla."));
        assertThat(locked(username)).isTrue();
        assertThat(audited(username, "ACCOUNT_LOCKED")).isEqualTo(1);

        List<AccountUnlockRequested> sent = unlockEmails(username);
        assertThat(sent).hasSize(1);
        assertThat(sent.get(0).email()).isEqualTo(username + "@example.com");
        String token = sent.get(0).token();
        List<String> hashes = jdbcTemplate.queryForList("""
                SELECT t.token_hash FROM account_unlock_tokens t JOIN users u ON u.id = t.user_id
                WHERE u.username = ?
                """, String.class, username);
        assertThat(hashes).hasSize(1).doesNotContain(token);

        // While locked, even the right password is refused, and no other email is sent.
        login(username, PASSWORD)
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString(
                        "usa el enlace que te enviamos por correo")));
        assertThat(unlockEmails(username)).hasSize(1);

        postJson("/api/v1/auth/unlock", Map.of("token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Tu cuenta quedó desbloqueada. Ya puedes iniciar sesión."));
        assertThat(locked(username)).isFalse();
        assertThat(audited(username, "ACCOUNT_UNLOCKED")).isEqualTo(1);
        login(username, PASSWORD).andExpect(status().isOk());

        // The link works only once.
        postJson("/api/v1/auth/unlock", Map.of("token", token))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_UNLOCK_TOKEN"));
    }

    @Test
    void anAccountWithoutEmailIsLockedWithoutAnUnlockLink() throws Exception {
        String username = newAccount();
        failFourTimes(username);

        login(username, WRONG_PASSWORD)
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.message").value("Demasiados intentos fallidos: la cuenta quedó bloqueada "
                        + "durante 30 minutos. Intenta de nuevo cuando termine el bloqueo."));
        assertThat(unlockEmails(username)).isEmpty();

        login(username, PASSWORD)
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.minutesLeft").value(30))
                .andExpect(jsonPath("$.message").value("La cuenta está bloqueada por demasiados intentos "
                        + "fallidos. Intenta de nuevo en 30 minutos."));
    }

    /** Registers an account through the API and returns the token of its verification email. */
    private String registerAndGetVerificationToken(String username) throws Exception {
        postJson("/api/v1/auth/register", Map.of(
                "username", username, "email", username + "@example.com", "password", PASSWORD))
                .andExpect(status().isCreated());
        List<VerificationEmailRequested> sent = events.stream(VerificationEmailRequested.class)
                .filter(event -> event.username().equals(username))
                .toList();
        assertThat(sent).hasSize(1);
        return sent.get(0).token();
    }

    private String lockedUntil(String username) {
        return jdbcTemplate.queryForObject("SELECT locked_until::text FROM users WHERE username = ?",
                String.class, username);
    }

    @Test
    void anAlreadyUsedVerificationLink_neitherLogsInNorUnlocksALockedAccount() throws Exception {
        String username = "lockv" + Long.toString(System.nanoTime(), 36);
        String token = registerAndGetVerificationToken(username);
        postJson("/api/v1/auth/verify-email", Map.of("token", token)).andExpect(status().isOk());
        failFourTimes(username);
        login(username, WRONG_PASSWORD).andExpect(status().isLocked());
        String lockedUntil = lockedUntil(username);

        postJson("/api/v1/auth/verify-email", Map.of("token", token))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_VERIFICATION_TOKEN"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(cookie().doesNotExist("refresh_token"));

        assertThat(locked(username)).isTrue();
        assertThat(lockedUntil(username)).isEqualTo(lockedUntil);
        login(username, PASSWORD).andExpect(status().isLocked());
    }

    @Test
    void anUnusedVerificationLink_doesNotStartASessionWhileTheAccountIsLocked() throws Exception {
        // The password is checked (and failures counted) before the email, so an unverified
        // account can be locked too.
        String username = "lockn" + Long.toString(System.nanoTime(), 36);
        String token = registerAndGetVerificationToken(username);
        failFourTimes(username);
        login(username, WRONG_PASSWORD).andExpect(status().isLocked());

        postJson("/api/v1/auth/verify-email", Map.of("token", token))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.errorCode").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(cookie().doesNotExist("refresh_token"));
        assertThat(locked(username)).isTrue();

        // The link is not used up: it works once the lock is over.
        jdbcTemplate.update("UPDATE users SET locked_until = now() - interval '1 second' WHERE username = ?",
                username);
        postJson("/api/v1/auth/verify-email", Map.of("token", token)).andExpect(status().isOk());
    }

    @Test
    void aSessionFromBeforeTheLock_cannotBeRenewedWhileTheAccountIsLocked() throws Exception {
        String username = newAccountWithVerifiedEmail();
        Cookie refresh = login(username, PASSWORD).andExpect(status().isOk())
                .andReturn().getResponse().getCookie("refresh_token");
        failFourTimes(username);
        login(username, WRONG_PASSWORD).andExpect(status().isLocked());

        mockMvc.perform(post("/api/v1/auth/refresh").cookie(refresh))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.errorCode").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(cookie().doesNotExist("refresh_token"));

        // Unlocking with the emailed link lets that same session go on.
        postJson("/api/v1/auth/unlock", Map.of("token", unlockEmails(username).get(0).token()))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/auth/refresh").cookie(refresh)).andExpect(status().isOk());
    }

    @Test
    void anExpiredUnlockLinkIsRejected() throws Exception {
        String username = newAccountWithVerifiedEmail();
        failFourTimes(username);
        login(username, WRONG_PASSWORD).andExpect(status().isLocked());
        jdbcTemplate.update("""
                UPDATE account_unlock_tokens SET expires_at = now() - interval '1 minute'
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                """, username);

        postJson("/api/v1/auth/unlock", Map.of("token", unlockEmails(username).get(0).token()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_UNLOCK_TOKEN"));
        postJson("/api/v1/auth/unlock", Map.of("token", "token-inventado"))
                .andExpect(status().isBadRequest());
        assertThat(locked(username)).isTrue();
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
    void anUnknownUserIsAudited_andWarnedWithoutACount() throws Exception {
        String username = "nadie" + Long.toString(System.nanoTime(), 36);

        login(username, WRONG_PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.attemptsLeft").doesNotExist())
                .andExpect(jsonPath("$.message").value("Credenciales inválidas. Después de 5 intentos fallidos, "
                        + "la cuenta se bloquea durante 30 minutos."));

        assertThat(audited(username, "LOGIN_FAILURE")).isEqualTo(1);
    }
}
