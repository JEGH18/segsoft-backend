package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.service.PasswordChanged;
import co.icesi.pdgseg.service.PasswordResetRequested;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Password recovery against PostgreSQL: the link goes only to verified emails, works once, sets a
 * password that follows the registration rules, ends every session opened before and lifts a lock.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "cors.allowed-origins=http://localhost:5173",
                "auth.registration.max-per-ip-per-hour=1000",
                // No SMTP in the tests: the link goes to the log and the token comes from the event.
                "auth.email-verification.log-links=true"
        }
)
@AutoConfigureMockMvc
@RecordApplicationEvents
class PasswordResetIntegrationTest extends PostgreSQLContainerBase {

    private static final String OLD_PASSWORD = "Clave-Original-2026!";
    private static final String NEW_PASSWORD = "Clave-Recuperada-2026!";
    private static final String CHECK_YOUR_EMAIL =
            "Si el correo pertenece a una cuenta, te enviamos un enlace para cambiar la contraseña. Vence en 30 minutos.";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private ApplicationEvents events;

    /** A DEVELOPER with a verified email, like a self-registered account; unique per run. */
    private String newAccount() {
        String username = "reset" + Long.toString(System.nanoTime(), 36);
        jdbcTemplate.update("""
                INSERT INTO users (username, password_hash, email, email_verified_at) VALUES (?, ?, ?, now())
                """, username, passwordEncoder.encode(OLD_PASSWORD), username + "@example.com");
        jdbcTemplate.update("""
                INSERT INTO user_roles (user_id, role_id)
                SELECT u.id, r.id FROM users u, roles r WHERE u.username = ? AND r.name = 'DEVELOPER'
                """, username);
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

    private ResultActions forgot(String email) throws Exception {
        return postJson("/api/v1/auth/forgot-password", Map.of("email", email));
    }

    private ResultActions reset(String token, String password) throws Exception {
        return postJson("/api/v1/auth/reset-password", Map.of("token", token, "password", password));
    }

    private List<PasswordResetRequested> resetEmails(String username) {
        return events.stream(PasswordResetRequested.class)
                .filter(event -> event.username().equals(username))
                .toList();
    }

    /** Asks for a link and returns the token of the email. */
    private String requestLink(String username) throws Exception {
        forgot(username + "@example.com").andExpect(status().isAccepted());
        List<PasswordResetRequested> sent = resetEmails(username);
        assertThat(sent).hasSize(1);
        return sent.get(0).token();
    }

    private int audited(String username, String eventType) {
        return jdbcTemplate.queryForObject(
                "SELECT count(*) FROM auth_audit_log WHERE username = ? AND event_type = ?",
                Integer.class, username, eventType);
    }

    @Test
    void theLinkSetsANewPassword_endsTheOpenSessions_andWorksOnlyOnce() throws Exception {
        String username = newAccount();
        MvcResult session = login(username, OLD_PASSWORD).andExpect(status().isOk()).andReturn();
        String accessToken = objectMapper.readTree(session.getResponse().getContentAsString())
                .get("accessToken").asText();
        Cookie refresh = session.getResponse().getCookie("refresh_token");

        String token = requestLink(username);
        assertThat(jdbcTemplate.queryForList("""
                SELECT t.token_hash FROM password_reset_tokens t JOIN users u ON u.id = t.user_id WHERE u.username = ?
                """, String.class, username)).hasSize(1).doesNotContain(token);

        // The registration rules apply; a rejected password does not use up the link.
        reset(token, "corta")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
        reset(token, OLD_PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("La contraseña nueva debe ser distinta de la actual."));

        reset(token, NEW_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(
                        "Tu contraseña cambió y cerramos las sesiones abiertas. Ya puedes iniciar sesión con la nueva."))
                .andExpect(jsonPath("$.accessToken").doesNotExist());
        assertThat(audited(username, "PASSWORD_RESET")).isEqualTo(1);
        assertThat(events.stream(PasswordChanged.class).filter(e -> e.username().equals(username))).hasSize(1);

        // The session opened before the change is over, on both of its tokens.
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("SESSION_REVOKED"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("contraseña")));
        mockMvc.perform(post("/api/v1/auth/refresh").cookie(refresh)).andExpect(status().isUnauthorized());

        login(username, OLD_PASSWORD).andExpect(status().isUnauthorized());
        String newAccess = objectMapper.readTree(login(username, NEW_PASSWORD).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("accessToken").asText();
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isOk());

        reset(token, "Otra-Clave-Nueva-2026!")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_RESET_TOKEN"));
    }

    @Test
    void theAnswerIsTheSame_whetherOrNotTheEmailHasAnAccount() throws Exception {
        String withoutEmail = "resetsin" + Long.toString(System.nanoTime(), 36);
        jdbcTemplate.update("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                withoutEmail, passwordEncoder.encode(OLD_PASSWORD));
        String unverified = newAccount();
        jdbcTemplate.update("UPDATE users SET email_verified_at = NULL WHERE username = ?", unverified);

        forgot("nadie-" + System.nanoTime() + "@example.com")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value(CHECK_YOUR_EMAIL));
        forgot(unverified + "@example.com")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value(CHECK_YOUR_EMAIL));

        assertThat(resetEmails(unverified)).isEmpty();
        assertThat(events.stream(PasswordResetRequested.class)).isEmpty();
    }

    @Test
    void aNewLinkInvalidatesThePreviousOne_andRequestsWaitForTheCooldown() throws Exception {
        String username = newAccount();
        String first = requestLink(username);

        forgot(username + "@example.com").andExpect(status().isAccepted());
        assertThat(resetEmails(username)).hasSize(1); // within the cooldown: no second email

        jdbcTemplate.update("""
                UPDATE password_reset_tokens SET created_at = now() - interval '2 minutes'
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                """, username);
        forgot(username + "@example.com").andExpect(status().isAccepted());
        assertThat(resetEmails(username)).hasSize(2);
        String second = resetEmails(username).get(1).token();

        reset(first, NEW_PASSWORD).andExpect(status().isBadRequest());
        reset(second, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void anExpiredLinkIsRejected() throws Exception {
        String username = newAccount();
        String token = requestLink(username);
        jdbcTemplate.update("""
                UPDATE password_reset_tokens SET expires_at = now() - interval '1 second'
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                """, username);

        reset(token, NEW_PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_RESET_TOKEN"));
        login(username, OLD_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void changingThePasswordLiftsALockFromFailedLogins() throws Exception {
        String username = newAccount();
        for (int i = 0; i < 5; i++) {
            login(username, "Clave-Incorrecta-2026!");
        }
        login(username, OLD_PASSWORD).andExpect(status().isLocked());

        reset(requestLink(username), NEW_PASSWORD).andExpect(status().isOk());

        login(username, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void aLinkSentSeveralTimesAtOnce_changesThePasswordOnlyOnce() throws Exception {
        String username = newAccount();
        String token = requestLink(username);
        int times = 8;
        ExecutorService pool = Executors.newFixedThreadPool(times);
        List<Integer> statuses = new ArrayList<>();
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Integer>> results = new ArrayList<>();
            for (int i = 0; i < times; i++) {
                String password = NEW_PASSWORD + i;
                results.add(pool.submit(() -> {
                    start.await();
                    return reset(token, password).andReturn().getResponse().getStatus();
                }));
            }
            start.countDown();
            for (Future<Integer> result : results) {
                statuses.add(result.get(60, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(statuses).containsOnly(200, 400).filteredOn(s -> s == 200).hasSize(1);
        assertThat(audited(username, "PASSWORD_RESET")).isEqualTo(1);
    }
}
