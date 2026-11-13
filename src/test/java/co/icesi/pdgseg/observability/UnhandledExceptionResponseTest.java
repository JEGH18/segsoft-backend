package co.icesi.pdgseg.observability;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import co.icesi.pdgseg.exception.GlobalExceptionHandler;
import co.icesi.pdgseg.service.AuditService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Escenario 4: an unhandled exception reaches the client as a fixed 500 body with the traceId,
 * no stack trace; the stack trace is in the log under that same traceId.
 */
class UnhandledExceptionResponseTest {

    @RestController
    static class FailingController {
        @GetMapping("/boom")
        String boom() {
            throw new IllegalStateException("Fallo interno con detalle sensible: jdbc://db:5432");
        }
    }

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Logger handlerLogger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        logs.start();
        handlerLogger.addAppender(logs);
        mockMvc = MockMvcBuilders.standaloneSetup(new FailingController())
                .setControllerAdvice(new GlobalExceptionHandler(mock(AuditService.class)))
                .addFilters(new TraceIdFilter())
                .build();
    }

    @AfterEach
    void tearDown() {
        handlerLogger.detachAppender(logs);
    }

    @Test
    void theClientGetsOnlyTheErrorCodeTheTraceIdAndAFixedMessage() throws Exception {
        MvcResult result = mockMvc.perform(get("/boom"))
                .andExpect(status().isInternalServerError())
                .andReturn();

        String raw = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        JsonNode body = objectMapper.readTree(raw);
        String traceId = result.getResponse().getHeader(TraceIdFilter.HEADER);

        assertThat(body.size()).isEqualTo(3);
        assertThat(body.path("errorCode").asText()).isEqualTo("INTERNAL_ERROR");
        assertThat(body.path("message").asText()).isEqualTo("Ocurrió un error inesperado");
        assertThat(body.path("traceId").asText()).isEqualTo(traceId).isNotBlank();
        assertThat(raw)
                .doesNotContain("IllegalStateException")
                .doesNotContain("jdbc://")
                .doesNotContain("at co.icesi");
    }

    @Test
    void theStackTraceIsLoggedUnderTheSameTraceId() throws Exception {
        MvcResult result = mockMvc.perform(get("/boom")).andReturn();
        String traceId = objectMapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8)).path("traceId").asText();

        assertThat(logs.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel().toString()).isEqualTo("ERROR");
            assertThat(event.getMDCPropertyMap()).containsEntry("traceId", traceId);
            assertThat(event.getThrowableProxy()).isNotNull();
            assertThat(event.getThrowableProxy().getClassName()).isEqualTo(IllegalStateException.class.getName());
            assertThat(event.getThrowableProxy().getStackTraceElementProxyArray()).isNotEmpty();
        });
    }
}
