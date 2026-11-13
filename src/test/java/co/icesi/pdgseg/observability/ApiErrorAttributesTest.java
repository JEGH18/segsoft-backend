package co.icesi.pdgseg.observability;

import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The /error page (errors outside the controllers) follows the same contract as GlobalExceptionHandler. */
class ApiErrorAttributesTest {

    private Map<String, Object> errorBody(int status, Throwable error) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/error");
        request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, status);
        request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, error);
        request.setAttribute(TraceIdFilter.MDC_KEY, "trace-from-filter-0001");
        return new ApiErrorAttributes().getErrorAttributes(new ServletWebRequest(request),
                ErrorAttributeOptions.of(ErrorAttributeOptions.Include.values()));
    }

    @Test
    void anUnhandledErrorIsReducedToErrorCodeMessageAndTraceId() {
        Map<String, Object> body = errorBody(500, new IllegalStateException("password=secreta en jdbc://db"));

        assertThat(body).containsOnlyKeys("errorCode", "message", "traceId");
        assertThat(body).containsEntry("errorCode", "INTERNAL_ERROR")
                .containsEntry("message", "Ocurrió un error inesperado")
                .containsEntry("traceId", "trace-from-filter-0001");
    }

    @Test
    void clientErrorsKeepTheirStatusNameAsErrorCode() {
        assertThat(errorBody(404, null)).containsEntry("errorCode", "NOT_FOUND").containsKey("traceId");
    }
}
