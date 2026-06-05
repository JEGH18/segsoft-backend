package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.response.FindingDetailResponse;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.service.FindingService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/findings")
@Tag(name = "Findings", description = "Endpoints para consultar detalles de hallazgos")
public class FindingController {

    private final FindingService findingService;

    public FindingController(FindingService findingService) {
        this.findingService = findingService;
    }

    @GetMapping("/{id}")
    @PreAuthorize("@analysisAuthorizationService.canAccessFinding(#id, authentication)")
    @Operation(summary = "Consultar detalle de finding", description = "Retorna detalle completo de un finding")
    public ResponseEntity<FindingDetailResponse> getFindingById(
            @PathVariable UUID id,
            @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch
    ) {
        Analysis analysis = findingService.getAnalysisByFindingId(id);
        if (analysis.getCompletedAt() != null) {
            String eTag = "\"" + analysis.getId() + "-" + analysis.getCompletedAt().toInstant().toEpochMilli() + "\"";
            if (eTag.equals(ifNoneMatch)) {
                return ResponseEntity.status(304).eTag(eTag).build();
            }
            return ResponseEntity.ok().eTag(eTag).body(findingService.getFindingDetail(id));
        }
        return ResponseEntity.ok(findingService.getFindingDetail(id));
    }
}
