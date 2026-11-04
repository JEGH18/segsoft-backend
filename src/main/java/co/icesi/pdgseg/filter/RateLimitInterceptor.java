package co.icesi.pdgseg.filter;

import co.icesi.pdgseg.security.ClientIpResolver;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final int LIMIT_PER_MINUTE = 60;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final ClientIpResolver clientIpResolver;

    public RateLimitInterceptor(ClientIpResolver clientIpResolver) {
        this.clientIpResolver = clientIpResolver;
    }

    private Bucket getBucket(String key) {
        return buckets.computeIfAbsent(key, k -> Bucket.builder()
            .addLimit(Bandwidth.classic(LIMIT_PER_MINUTE,
                Refill.greedy(LIMIT_PER_MINUTE, Duration.ofMinutes(1))))
            .build());
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        // Not getRemoteAddr(): behind Caddy that is Caddy's address, shared by every caller.
        String ip = clientIpResolver.resolve(request);
        String user = (request.getUserPrincipal() != null)
            ? request.getUserPrincipal().getName()
            : "anonymous";
        String key = ip + ":" + user;

        ConsumptionProbe probe = getBucket(key).tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed()) {
            response.setHeader("X-Rate-Limit-Remaining",
                String.valueOf(probe.getRemainingTokens()));
            return true;
        }

        long retryAfterSeconds = probe.getNanosToWaitForRefill() / 1_000_000_000L;
        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
            "{\"errorCode\":\"TOO_MANY_REQUESTS\","
            + "\"message\":\"Límite de 60 solicitudes por minuto excedido. "
            + "Intente de nuevo en " + retryAfterSeconds + " segundos.\"}");
        return false;
    }
}
