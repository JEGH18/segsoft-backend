package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.StartAnalysisRequest;
import co.icesi.pdgseg.dto.response.AnalysisResponse;
import co.icesi.pdgseg.dto.response.AnalysisResultsResponse;
import co.icesi.pdgseg.dto.response.FindingResponse;
import co.icesi.pdgseg.service.AnalysisService;
import co.icesi.pdgseg.service.FindingService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/analyses")
@Tag(name = "Análisis", description = "Endpoints para ejecutar y consultar análisis de cumplimiento")
public class AnalysisController {

    private final AnalysisService analysisService;
    private final FindingService findingService;

    public AnalysisController(AnalysisService analysisService, FindingService findingService) {
        this.analysisService = analysisService;
        this.findingService = findingService;
    }

    @PostMapping
    @PreAuthorize("@analysisAuthorizationService.canAccessRepository(#request.repositoryId(), authentication)")
    @Operation(summary = "Crear análisis", description = "Crea un análisis en estado QUEUED y dispara ejecución asíncrona")
    public ResponseEntity<AnalysisResponse> create(
            @Valid @RequestBody StartAnalysisRequest request,
            @RequestHeader(value = "X-Trace-Id", required = false) String traceId,
            Authentication authentication
    ) {
        AnalysisResponse response = analysisService.startAnalysis(request.repositoryId(), authentication.getName(), traceId);
        return ResponseEntity.accepted().body(response);
    }

    @GetMapping("/{id}")
    @PreAuthorize("@analysisAuthorizationService.canAccessAnalysis(#id, authentication)")
    @Operation(summary = "Consultar análisis", description = "Retorna el estado actual del análisis")
    public ResponseEntity<AnalysisResponse> get(@PathVariable UUID id) {
        return ResponseEntity.ok(analysisService.getAnalysis(id));
    }

    @GetMapping("/{id}/results")
    @PreAuthorize("@analysisAuthorizationService.canAccessAnalysis(#id, authentication)")
    @Operation(summary = "Consultar resultados", description = "Retorna findings, policy results, errores y agregados")
    public ResponseEntity<AnalysisResultsResponse> getResults(
            @PathVariable UUID id,
            @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch
    ) {
        return etagResponse(id, ifNoneMatch, analysisService.getResults(id));
    }

    @GetMapping("/{id}/findings")
    @PreAuthorize("@analysisAuthorizationService.canAccessAnalysis(#id, authentication)")
    @Operation(summary = "Consultar findings", description = "Retorna findings filtrados y paginados de un análisis")
    public ResponseEntity<Page<FindingResponse>> getFindings(
            @PathVariable UUID id,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) UUID policyId,
            @RequestParam(required = false) String filePath,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<FindingResponse> response = findingService.getFindings(
                id,
                splitCsv(severity),
                splitCsv(category),
                policyId,
                filePath,
                pageable
        );
        return etagResponse(id, ifNoneMatch, response);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("@analysisAuthorizationService.canAccessAnalysis(#id, authentication)")
    @Operation(summary = "Cancelar análisis", description = "Cancela el análisis y descarta resultados parciales")
    public ResponseEntity<Void> cancel(@PathVariable UUID id) {
        analysisService.cancelAnalysis(id);
        return ResponseEntity.noContent().build();
    }

    private <T> ResponseEntity<T> etagResponse(UUID analysisId, String ifNoneMatch, T body) {
        OffsetDateTime completedAt = analysisService.getAnalysisEntity(analysisId).getCompletedAt();
        if (completedAt == null) {
            return ResponseEntity.ok(body);
        }
        String eTag = "\"" + analysisId + "-" + completedAt.toInstant().toEpochMilli() + "\"";
        if (eTag.equals(ifNoneMatch)) {
            return ResponseEntity.status(304).eTag(eTag).build();
        }
        return ResponseEntity.ok().eTag(eTag).body(body);
    }

    private List<String> splitCsv(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(v -> !v.isEmpty())
                .toList();
    }
}
