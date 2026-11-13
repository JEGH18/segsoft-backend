package co.icesi.pdgseg.observability.health;

import co.icesi.pdgseg.observability.TraceIdFilter;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Readiness of the Python engine: a ping to its /internal/health, with the service token and a
 * short timeout so a hung engine does not hang the health check. Component "engine" in
 * /actuator/health/readiness. Neither the URL nor the token is in the response.
 */
@Component("engine")
public class EngineHealthIndicator implements HealthIndicator {

    private final RestTemplate restTemplate;
    private final String healthUrl;
    private final String serviceToken;

    public EngineHealthIndicator(
            @Value("${engine.base-url}") String baseUrl,
            @Value("${engine.service-token}") String serviceToken,
            @Value("${engine.health-timeout-ms:2000}") int timeoutMs
    ) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(timeoutMs);
        requestFactory.setReadTimeout(timeoutMs);
        this.restTemplate = new RestTemplate(requestFactory);
        this.healthUrl = baseUrl + "/internal/health";
        this.serviceToken = serviceToken;
    }

    @Override
    public Health health() {
        long started = System.nanoTime();
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Service-Token", serviceToken);
        String traceId = TraceIdFilter.current();
        if (traceId != null) {
            headers.set(TraceIdFilter.HEADER, traceId);
        }
        try {
            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    healthUrl, HttpMethod.GET, new HttpEntity<>(headers), JsonNode.class);
            JsonNode body = response.getBody();
            if (body == null || !"ok".equalsIgnoreCase(body.path("status").asText())) {
                return Health.down().withDetail("error", "Respuesta inesperada del motor").build();
            }
            return Health.up().withDetail("responseTimeMs", PostgresHealthIndicator.elapsedMs(started)).build();
        } catch (RestClientException ex) {
            return Health.down().withDetail("error", ex.getClass().getSimpleName()).build();
        }
    }
}
