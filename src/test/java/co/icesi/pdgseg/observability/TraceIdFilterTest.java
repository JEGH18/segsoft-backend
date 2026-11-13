package co.icesi.pdgseg.observability;

import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class TraceIdFilterTest {

    @Test
    void generatesAUuidV4WhenTheCallerSendsNone() {
        String traceId = TraceIdFilter.resolve(null, null);
        assertThat(UUID.fromString(traceId).version()).isEqualTo(4);
    }

    @Test
    void keepsAWellFormedTraceIdFromTheCaller() {
        String own = UUID.randomUUID().toString();
        assertThat(TraceIdFilter.resolve(own, null)).isEqualTo(own);
    }

    @Test
    void takesTheTraceIdOfAW3cTraceparent() {
        assertThat(TraceIdFilter.resolve(null, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"))
                .isEqualTo("4bf92f3577b34da6a3ce929d0e0e4736");
    }

    @Test
    void replacesValuesThatCouldForgeLogLines() {
        for (String bad : new String[]{"short", "a b c d e f g h i j k l", "x\n{\"level\":\"ERROR\"}", "x".repeat(65)}) {
            assertThat(UUID.fromString(TraceIdFilter.resolve(bad, "garbage"))).isNotNull();
        }
    }

    @Test
    void theTraceIdIsInTheMdcDuringTheRequestInTheResponseAndGoneAfterwards() throws Exception {
        AtomicReference<String> seen = new AtomicReference<>();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/anything");
        MockHttpServletResponse response = new MockHttpServletResponse();

        new TraceIdFilter().doFilter(request, response,
                new MockFilterChain(new jakarta.servlet.http.HttpServlet() {}) {
                    @Override
                    public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                        seen.set(MDC.get("traceId"));
                    }
                });

        assertThat(seen.get()).isNotBlank();
        assertThat(response.getHeader("X-Trace-Id")).isEqualTo(seen.get());
        assertThat(request.getAttribute("traceId")).isEqualTo(seen.get());
        assertThat(MDC.get("traceId")).isNull();
    }
}
