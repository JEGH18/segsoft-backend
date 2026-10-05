package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.service.ReportService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/analyses/{analysisId}/reports")
@PreAuthorize("hasAnyRole('AUDITOR', 'SECURITY_ADMIN')")
@Tag(name = "Reportes", description = "Generación y exportación de reportes de cumplimiento")
public class AnalysisReportController {

    private final ReportService reportService;

    public AnalysisReportController(ReportService reportService) {
        this.reportService = reportService;
    }

    @PostMapping
    @Operation(summary = "Generar reporte",
            description = "Congela los resultados de un análisis COMPLETED en un reporte inmutable con checksum "
                    + "SHA-256. 201 con la URL del reporte (header Location); 404 si el análisis no existe; 422 si "
                    + "no está COMPLETED")
    public ResponseEntity<ReportResponse> generate(@PathVariable UUID analysisId, Authentication authentication) {
        ReportResponse report = reportService.generate(analysisId, authentication.getName());
        return ResponseEntity.created(URI.create(report.url())).body(report);
    }
}
