package co.icesi.pdgseg.observability;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Gives every HTTP request a traceId before anything else runs (Spring Security included), so
 * every log line written while serving it, and every error body, carries the same id. The id
 * goes back in the X-Trace-Id response header and on to the engine (EngineClient).
 *
 * <p>A caller may send its own id, in X-Trace-Id or as the trace-id of a W3C traceparent
 * header, to correlate with its own logs. It is only accepted with a safe shape: an arbitrary
 * header value would otherwise be written into every log line (log forging).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TraceIdFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TraceIdFilter.class);

    public static final String MDC_KEY = "traceId";
    public static final String HEADER = "X-Trace-Id";

    /** UUID or any 8-64 character id made of letters, digits and dashes (same rule in the engine). */
    private static final Pattern SAFE_TRACE_ID = Pattern.compile("[A-Za-z0-9-]{8,64}");

    /** W3C Trace Context: version-traceid-parentid-flags. */
    private static final Pattern TRACEPARENT = Pattern.compile("[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String traceId = resolve(request.getHeader(HEADER), request.getHeader("traceparent"));
        MDC.put(MDC_KEY, traceId);
        // For the /error page, rendered after this filter has returned (ApiErrorAttributes).
        request.setAttribute(MDC_KEY, traceId);
        response.setHeader(HEADER, traceId);
        try {
            chain.doFilter(request, response);
        } catch (ServletException | IOException | RuntimeException ex) {
            // Thrown outside the controllers (GlobalExceptionHandler logs those): logged here,
            // while the traceId is still in the MDC. The client gets the /error page.
            log.error("Excepción no manejada en {} {}", request.getMethod(), request.getRequestURI(), ex);
            throw ex;
        } finally {
            MDC.remove(MDC_KEY);
        }
    }

    static String resolve(String traceIdHeader, String traceparentHeader) {
        if (traceIdHeader != null && SAFE_TRACE_ID.matcher(traceIdHeader).matches()) {
            return traceIdHeader;
        }
        if (traceparentHeader != null) {
            var matcher = TRACEPARENT.matcher(traceparentHeader.trim());
            if (matcher.matches()) {
                return matcher.group(1);
            }
        }
        return UUID.randomUUID().toString();
    }

    /** The traceId of the request being served on this thread, or null outside of one. */
    public static String current() {
        return MDC.get(MDC_KEY);
    }
}
