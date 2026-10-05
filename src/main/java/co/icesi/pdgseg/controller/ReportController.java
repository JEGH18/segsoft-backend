package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.response.ReportSummaryResponse;
import co.icesi.pdgseg.dto.response.StructuredReportResponse;
import co.icesi.pdgseg.service.ReportService;
import co.icesi.pdgseg.service.ReportView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/reports")
@PreAuthorize("hasAnyRole('AUDITOR', 'SECURITY_ADMIN')")
@Tag(name = "Reportes", description = "Generación y exportación de reportes de cumplimiento")
public class ReportController {

    static final String X_CACHE = "X-Cache";

    private final ReportService reportService;

    public ReportController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping
    @Operation(summary = "Histórico de reportes",
            description = "Reportes generados, del más reciente al más antiguo; filtrable por repositorio o análisis")
    public ResponseEntity<Page<ReportSummaryResponse>> list(
            @RequestParam(required = false) UUID repositoryId,
            @RequestParam(required = false) UUID analysisId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        PageRequest pageable = PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100));
        return ResponseEntity.ok(reportService.list(repositoryId, analysisId, pageable));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Consultar reporte",
            description = "Reporte estructurado: metadata, executiveSummary, policyResults, findingsBySeverity, "
                    + "claudeCodeSecurityCoverage, frameworkCoverage y traceabilityReference. view=executive omite "
                    + "el detalle técnico (políticas, hallazgos y snippets). 409 si el checksum no coincide")
    public ResponseEntity<StructuredReportResponse> get(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "technical") String view,
            Authentication authentication
    ) {
        return ResponseEntity.ok(reportService.get(id, ReportView.parse(view), authentication.getName()));
    }

    @GetMapping("/{id}/export")
    @Operation(summary = "Exportar reporte",
            description = "Exporta el reporte en el formato solicitado (pdf, sarif). Sirve el archivo desde caché "
                    + "cuando existe (X-Cache: HIT) o lo genera (X-Cache: MISS). 400 si el formato no está soportado, "
                    + "404 si el reporte no existe, 409 si su checksum no coincide con el contenido y 422 si el "
                    + "archivo supera MAX_EXPORT_SIZE_MB")
    public ResponseEntity<byte[]> export(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "pdf") String format,
            Authentication authentication
    ) {
        ExportedReport exported = reportService.export(id, format, authentication.getName());
        return ResponseEntity.ok()
                .contentType(exported.mediaType())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(exported.fileName()).build().toString())
                .cacheControl(CacheControl.noStore())
                .header(X_CACHE, exported.cacheHit() ? "HIT" : "MISS")
                .body(exported.content());
    }
}
