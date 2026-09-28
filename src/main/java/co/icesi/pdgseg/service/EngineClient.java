package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.engine.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class EngineClient {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final String serviceToken;

    public EngineClient(
            ObjectMapper objectMapper,
            @Value("${engine.base-url}") String baseUrl,
            @Value("${engine.service-token}") String serviceToken,
            @Value("${engine.connect-timeout-ms:5000}") int connectTimeoutMs,
            @Value("${engine.read-timeout-ms:60000}") int readTimeoutMs
    ) {
        this.objectMapper = objectMapper;
        this.baseUrl = baseUrl;
        this.serviceToken = serviceToken;
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(connectTimeoutMs);
        requestFactory.setReadTimeout(readTimeoutMs);
        this.restTemplate = new RestTemplate(requestFactory);
    }

    public ExecuteRuleResponse executeRule(ExecuteRuleRequest request, String traceId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Service-Token", serviceToken);
        headers.set("X-Trace-Id", traceId != null ? traceId : defaultTraceId());
        HttpEntity<ExecuteRuleRequest> entity = new HttpEntity<>(request, headers);

        try {
            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    baseUrl + "/internal/execute-rule",
                    HttpMethod.POST,
                    entity,
                    JsonNode.class
            );
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new IllegalStateException("Motor Python respondió estado no exitoso");
            }
            return parseEngineResponse(response.getBody());
        } catch (RestClientException ex) {
            throw new IllegalStateException("No se pudo ejecutar regla en motor Python", ex);
        }
    }

    private ExecuteRuleResponse parseEngineResponse(JsonNode body) {
        if (body.isArray()) {
            List<EngineFindingResponse> findings = objectMapper.convertValue(
                    body,
                    new TypeReference<>() {}
            );
            return new ExecuteRuleResponse(findings, List.of());
        }

        List<EngineFindingResponse> findings = body.has("findings")
                ? objectMapper.convertValue(body.get("findings"), new TypeReference<>() {})
                : Collections.emptyList();

        List<EngineRuleErrorResponse> errors = body.has("errors")
                ? objectMapper.convertValue(body.get("errors"), new TypeReference<>() {})
                : Collections.emptyList();

        return new ExecuteRuleResponse(findings, errors);
    }

    private String defaultTraceId() {
        String current = MDC.get("traceId");
        return current != null ? current : "unknown";
    }
}
