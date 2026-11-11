package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.engine.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class EngineClient {

    private static final Logger log = LoggerFactory.getLogger(EngineClient.class);

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final String serviceToken;

    /** False once the engine answered 404 to the batch endpoint (an engine older than this backend). */
    private volatile boolean batchSupported = true;

    public EngineClient(
            ObjectMapper objectMapper,
            @Value("${engine.base-url}") String baseUrl,
            @Value("${engine.service-token}") String serviceToken,
            @Value("${engine.connect-timeout-ms:5000}") int connectTimeoutMs,
            @Value("${engine.read-timeout-ms:180000}") int readTimeoutMs
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
        return post("/internal/execute-rule", request, traceId);
    }

    /**
     * Runs one rule over many files in a single request. Every finding and error in the answer
     * carries the filePath it belongs to, exactly as it was sent in artifactPaths.
     *
     * <p>If the engine does not have the batch endpoint yet (404, e.g. the backend was updated
     * before the engine), the files are sent one by one to /internal/execute-rule instead, and
     * the answer is the same.
     */
    public ExecuteRuleResponse executeRuleBatch(ExecuteRuleBatchRequest request, String traceId) {
        if (batchSupported) {
            try {
                return post("/internal/execute-rule-batch", request, traceId);
            } catch (IllegalStateException ex) {
                if (!(ex.getCause() instanceof HttpClientErrorException.NotFound)) {
                    throw ex;
                }
                batchSupported = false;
                log.warn("El motor no tiene /internal/execute-rule-batch; se ejecuta archivo por archivo");
            }
        }
        return executeOneByOne(request, traceId);
    }

    private ExecuteRuleResponse executeOneByOne(ExecuteRuleBatchRequest request, String traceId) {
        List<EngineFindingResponse> findings = new ArrayList<>();
        List<EngineRuleErrorResponse> errors = new ArrayList<>();
        for (String path : request.artifactPaths()) {
            ExecuteRuleResponse single = executeRule(new ExecuteRuleRequest(
                    request.ruleId(), request.type(), request.payload(), path,
                    request.category(), request.severity(), request.cweId()), traceId);
            for (EngineFindingResponse f : single.findings()) {
                findings.add(new EngineFindingResponse(path, f.lineNumber(), f.evidenceSnippet(), f.fileSha256(),
                        f.category(), f.severity(), f.cweId(), f.suggestedAction()));
            }
            for (EngineRuleErrorResponse e : single.errors()) {
                errors.add(new EngineRuleErrorResponse(e.errorCode(), e.message(), path));
            }
        }
        return new ExecuteRuleResponse(findings, errors);
    }

    private ExecuteRuleResponse post(String path, Object request, String traceId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Service-Token", serviceToken);
        headers.set("X-Trace-Id", traceId != null ? traceId : defaultTraceId());
        HttpEntity<Object> entity = new HttpEntity<>(request, headers);

        try {
            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    baseUrl + path,
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
