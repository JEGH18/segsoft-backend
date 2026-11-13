package co.icesi.pdgseg.observability;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Body of Spring Boot's /error page, used for errors raised outside the controllers (in a
 * filter, for instance): the same shape as GlobalExceptionHandler's, with the request's
 * traceId and never the exception, its message or the stack trace.
 */
@Component
public class ApiErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> defaults = super.getErrorAttributes(webRequest, ErrorAttributeOptions.defaults());
        int status = defaults.get("status") instanceof Integer code ? code : 500;

        Map<String, Object> body = new LinkedHashMap<>();
        if (status >= 500) {
            body.put("errorCode", "INTERNAL_ERROR");
            body.put("message", "Ocurrió un error inesperado");
        } else {
            body.put("errorCode", String.valueOf(defaults.getOrDefault("error", "ERROR"))
                    .toUpperCase(Locale.ROOT).replace(' ', '_'));
            body.put("message", defaults.getOrDefault("error", "Error"));
        }
        Object traceId = webRequest.getAttribute(TraceIdFilter.MDC_KEY, RequestAttributes.SCOPE_REQUEST);
        body.put("traceId", traceId != null ? traceId : "unknown");
        return body;
    }
}
