package co.icesi.pdgseg.integration;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import ch.qos.logback.core.encoder.Encoder;
import ch.qos.logback.core.read.ListAppender;
import co.icesi.pdgseg.observability.AnalysisMetrics;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Observability against a real PostgreSQL: the Actuator endpoints (liveness, readiness with its
 * three dependencies, health, info, prometheus), the traceId of each request and the JSON logs.
 * The engine is a stub HTTP server whose /internal/health can be switched off.
 */
@SpringBootTest(
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "cors.allowed-origins=http://localhost:5173",
                "sandbox.root=${java.io.tmpdir}/pdgseg-observability-it"
        }
)
@AutoConfigureMockMvc
// Spring Boot tests turn metrics export off; without this there is no /actuator/prometheus.
@AutoConfigureObservability(tracing = false)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ObservabilityIntegrationTest extends PostgreSQLContainerBase {

    private static final String ADMIN = "obs.admin";
    private static final String DEVELOPER = "obs.developer";
    private static final String PASSWORD = "Observability-2026!";
    private static final String SERVICE_TOKEN = "observability-it-service-token";

    private static final HttpServer ENGINE = startEngineStub();
    private static volatile boolean engineUp = true;

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private AnalysisMetrics analysisMetrics;

    @DynamicPropertySource
    static void engine(DynamicPropertyRegistry registry) {
        registry.add("engine.base-url", () -> "http://127.0.0.1:" + ENGINE.getAddress().getPort());
        registry.add("engine.service-token", () -> SERVICE_TOKEN);
    }

    /** /internal/health answers like the engine, and only with the service token. */
    private static HttpServer startEngineStub() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/internal/health", exchange -> {
                boolean authorized = SERVICE_TOKEN.equals(exchange.getRequestHeaders().getFirst("X-Service-Token"));
                int status = !authorized ? 401 : engineUp ? 200 : 503;
                byte[] body = (status == 200 ? "{\"status\":\"ok\"}" : "{\"detail\":\"down\"}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @BeforeAll
    void seedUsers() {
        seedUser(ADMIN, "SECURITY_ADMIN");
        seedUser(DEVELOPER, "DEVELOPER");
    }

    @AfterAll
    void stopEngine() {
        ENGINE.stop(0);
    }

    @BeforeEach
    void engineBackUp() {
        engineUp = true;
    }

    // ---- Escenario 1: liveness ---------------------------------------------------------------

    @Test
    void livenessIsPublicAnswersOnlyUpAndIsFast() throws Exception {
        mockMvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());

        long started = System.nanoTime();
        MvcResult result = mockMvc.perform(get("/actuator/health/liveness"))
                .andExpect(status().isOk())
                .andReturn();
        Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

        assertThat(objectMapper.readTree(result.getResponse().getContentAsString()))
                .isEqualTo(objectMapper.readTree("{\"status\":\"UP\"}"));
        assertThat(elapsed).isLessThan(Duration.ofMillis(100));

        // Nothing more for an authenticated user either: no components, versions or hosts.
        mockMvc.perform(get("/actuator/health/liveness").header("Authorization", "Bearer " + login(ADMIN)))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"status\":\"UP\"}", true));
    }

    // ---- Escenario 2: readiness ----------------------------------------------------------------

    @Test
    void readinessChecksPostgresSandboxAndEngine() throws Exception {
        mockMvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components.postgres.status").value("UP"))
                .andExpect(jsonPath("$.components.sandbox.status").value("UP"))
                .andExpect(jsonPath("$.components.engine.status").value("UP"))
                .andExpect(jsonPath("$.components.readinessState.status").value("UP"))
                // Anonymous: the status of each dependency, never its details.
                .andExpect(jsonPath("$.components.postgres.details").doesNotExist());

        mockMvc.perform(get("/actuator/health/readiness").header("Authorization", "Bearer " + login(ADMIN)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components.postgres.details.responseTimeMs").isNumber())
                .andExpect(jsonPath("$.components.sandbox.details.responseTimeMs").isNumber())
                .andExpect(jsonPath("$.components.engine.details.responseTimeMs").isNumber());
    }

    @Test
    void readinessAnswers503WhenTheEngineIsDown() throws Exception {
        engineUp = false;

        String body = mockMvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DOWN"))
                .andExpect(jsonPath("$.components.engine.status").value("DOWN"))
                .andExpect(jsonPath("$.components.postgres.status").value("UP"))
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("127.0.0.1").doesNotContain(SERVICE_TOKEN);

        // Liveness does not depend on the engine: the backend must not be restarted for it.
        mockMvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
    }

    // ---- health, info and prometheus -------------------------------------------------------------

    @Test
    void healthAndInfoArePublic() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
        mockMvc.perform(get("/actuator/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.build.artifact").value("pdgseg-backend"));
    }

    @Test
    void prometheusIsOnlyForSecurityAdminsAndHasTheAnalysisMetrics() throws Exception {
        analysisMetrics.ruleExecuted("PATTERN_REGEX", true, Duration.ofMillis(120));
        analysisMetrics.ruleError("PATTERN_REGEX", "RULE_TIMEOUT");

        mockMvc.perform(get("/actuator/prometheus")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/actuator/prometheus").header("Authorization", "Bearer " + login(DEVELOPER)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("FORBIDDEN"))
                .andExpect(jsonPath("$.traceId").isNotEmpty());

        String metrics = mockMvc.perform(get("/actuator/prometheus")
                        .header("Authorization", "Bearer " + login(ADMIN)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(metrics)
                .contains("analyses_executed_total{")
                .contains("analyses_running_current{")
                .contains("rule_execution_duration_seconds_bucket{")
                .contains("rule_execution_errors_total{")
                .contains("errorCode=\"RULE_TIMEOUT\"")
                .contains("http_server_requests_seconds_count{");
    }

    @Test
    void otherActuatorEndpointsAreNotReachable() throws Exception {
        mockMvc.perform(get("/actuator/env").header("Authorization", "Bearer " + login(ADMIN)))
                .andExpect(status().isForbidden());
    }

    @Test
    void anUnknownPathIsA404WithTraceIdNotAnUnexpectedError() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/no-existe").header("Authorization", "Bearer " + login(DEVELOPER)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("NOT_FOUND"))
                .andReturn();
        assertThat(objectMapper.readTree(result.getResponse().getContentAsString()).path("traceId").asText())
                .isEqualTo(result.getResponse().getHeader("X-Trace-Id"));
    }

    // ---- Escenario 3: traceId and JSON logs ------------------------------------------------------

    @Test
    void everyResponseCarriesItsTraceIdAndAKnownOneIsKept() throws Exception {
        String generated = mockMvc.perform(get("/actuator/health/liveness"))
                .andReturn().getResponse().getHeader("X-Trace-Id");
        assertThat(UUID.fromString(generated).version()).isEqualTo(4);

        String own = UUID.randomUUID().toString();
        mockMvc.perform(get("/actuator/health/liveness").header("X-Trace-Id", own))
                .andExpect(header().string("X-Trace-Id", own));

        mockMvc.perform(get("/actuator/health/liveness")
                        .header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"))
                .andExpect(header().string("X-Trace-Id", "4bf92f3577b34da6a3ce929d0e0e4736"));

        // A value that could forge log lines is replaced, not echoed.
        String forged = mockMvc.perform(get("/actuator/health/liveness").header("X-Trace-Id", "x{\"level\":\"ERROR\"}"))
                .andReturn().getResponse().getHeader("X-Trace-Id");
        assertThat(forged).doesNotContain("level");
        assertThat(UUID.fromString(forged)).isNotNull();
    }

    @Test
    void logsOfRequestsWithAuthorizationNeverContainTheTokenAndShareTheTraceId() throws Exception {
        String jwt = login(ADMIN);
        String apiToken = createApiToken(login(DEVELOPER));
        String traceId = UUID.randomUUID().toString();

        List<String> lines = captureJsonLogs(traceId, () -> {
            mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + jwt).header("X-Trace-Id", traceId))
                    .andExpect(status().isOk());
            mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + apiToken).header("X-Trace-Id", traceId))
                    .andExpect(status().isOk());
            // Even a careless log line in our own code, written while serving the same request.
            MDC.put("traceId", traceId);
            try {
                LoggerFactory.getLogger("co.icesi.pdgseg.ObservabilityIT").warn(
                        "login fallido password=Sup3rS3creta! Authorization: Bearer {}", jwt);
            } finally {
                MDC.remove("traceId");
            }
        });

        assertThat(lines).isNotEmpty();
        String all = String.join("\n", lines);
        assertThat(all)
                .doesNotContain(jwt)
                .doesNotContain(jwt.substring(jwt.lastIndexOf('.') + 1))
                .doesNotContain(apiToken)
                .doesNotContain("Sup3rS3creta!")
                .contains("*****");

        // The request headers were logged (masked): the test would prove nothing otherwise.
        assertThat(lines).filteredOn(line -> line.contains("DispatcherServlet") && line.contains("/api/v1/auth/me"))
                .anySatisfy(line -> assertThat(line).containsIgnoringCase("authorization").contains("Bearer *****"));

        for (String line : lines) {
            JsonNode json = objectMapper.readTree(line);
            assertThat(json.path("timestamp").asText()).matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z");
            assertThat(json.path("level").asText()).isIn("TRACE", "DEBUG", "INFO", "WARN", "ERROR");
            assertThat(json.path("message").isTextual()).isTrue();
            assertThat(json.path("logger").isTextual()).isTrue();
            assertThat(json.path("context").path("service").asText()).isEqualTo("pdgseg-backend");
            assertThat(json.path("traceId").asText()).isEqualTo(traceId);
        }
    }

    // ---- helpers ---------------------------------------------------------------------------------

    @FunctionalInterface
    private interface Requests {
        void run() throws Exception;
    }

    /**
     * Runs the requests with request logging at TRACE and returns every line with the given
     * traceId, as the application's CONSOLE appender (logback-spring.xml, masking included)
     * writes it.
     */
    private List<String> captureJsonLogs(String traceId, Requests requests) throws Exception {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger root = context.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        @SuppressWarnings("unchecked")
        Encoder<ILoggingEvent> encoder = ((OutputStreamAppender<ILoggingEvent>) consoleAppender(root)).getEncoder();

        ListAppender<ILoggingEvent> capture = new ListAppender<>();
        capture.setContext(context);
        capture.start();
        root.addAppender(capture);

        List<String> verbose = List.of("org.springframework.web", "org.springframework.test.web",
                "org.springframework.security", "co.icesi.pdgseg");
        List<Level> previous = new ArrayList<>();
        for (String name : verbose) {
            previous.add(context.getLogger(name).getLevel());
            context.getLogger(name).setLevel(Level.TRACE);
        }
        // DispatcherServlet then logs every request header, Authorization included: the worst
        // case, which only the log masking stands between and the log file.
        mockMvc.getDispatcherServlet().setEnableLoggingRequestDetails(true);
        try {
            requests.run();
        } finally {
            mockMvc.getDispatcherServlet().setEnableLoggingRequestDetails(false);
            root.detachAppender(capture);
            for (int i = 0; i < verbose.size(); i++) {
                context.getLogger(verbose.get(i)).setLevel(previous.get(i));
            }
        }

        List<String> lines = new ArrayList<>();
        for (ILoggingEvent event : capture.list) {
            // Only what was logged under this traceId: the requests and the explicit line.
            if (traceId.equals(event.getMDCPropertyMap().get("traceId"))) {
                lines.add(new String(encoder.encode(event), StandardCharsets.UTF_8).trim());
            }
        }
        return lines;
    }

    private static ch.qos.logback.core.Appender<ILoggingEvent> consoleAppender(Logger root) {
        for (Iterator<ch.qos.logback.core.Appender<ILoggingEvent>> it = root.iteratorForAppenders(); it.hasNext(); ) {
            ch.qos.logback.core.Appender<ILoggingEvent> appender = it.next();
            if ("CONSOLE".equals(appender.getName())) {
                return appender;
            }
        }
        throw new IllegalStateException("logback-spring.xml no configuró el appender CONSOLE");
    }

    private void seedUser(String username, String role) {
        jdbcTemplate.update(
                "INSERT INTO users (username, password_hash) VALUES (?, ?) "
                        + "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, "
                        + "enabled = true, locked_until = NULL",
                username, passwordEncoder.encode(PASSWORD));
        jdbcTemplate.update(
                "INSERT INTO user_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r "
                        + "WHERE u.username = ? AND r.name = ? ON CONFLICT DO NOTHING", username, role);
    }

    private String login(String username) throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("username", username, "password", PASSWORD))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).path("accessToken").asText();
    }

    private String createApiToken(String session) throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/api-tokens")
                        .header("Authorization", "Bearer " + session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("name", "obs-" + UUID.randomUUID(), "expiresInDays", 1))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).path("token").asText();
    }
}
