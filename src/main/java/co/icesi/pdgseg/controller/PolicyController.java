package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.CreatePolicyRequest;
import co.icesi.pdgseg.dto.request.UpdatePolicyRequest;
import co.icesi.pdgseg.dto.response.CategoryCoverageItem;
import co.icesi.pdgseg.dto.response.PolicyAuditLogEntryResponse;
import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.dto.response.PolicyTraceabilityResponse;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.service.PolicyService;

import java.util.List;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/policies")
@Tag(name = "Políticas", description = "Gestión del banco de políticas de seguridad")
@SecurityRequirement(name = "bearerAuth")
public class PolicyController {

    private final PolicyService policyService;

    public PolicyController(PolicyService policyService) {
        this.policyService = policyService;
    }

    @GetMapping("/coverage")
    @Operation(
        summary = "Cobertura de políticas por categoría",
        description = "Retorna para cada una de las 5 categorías CCS: políticas activas y ejecutables."
    )
    public List<CategoryCoverageItem> coverage() {
        return policyService.getCoverage();
    }

    @GetMapping
    @Operation(
        summary = "Listar políticas",
        description = "Listado paginado con filtros opcionales. Accesible para todos los roles autenticados."
    )
    public ResponseEntity<Page<PolicyResponse>> list(
            @RequestParam(required = false) Framework framework,
            @RequestParam(required = false) Category category,
            @RequestParam(required = false) PolicyStatus status,
            @RequestParam(required = false) String name,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        if (size > 100) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "El tamaño máximo de página es 100");
        }

        PageRequest pageable = PageRequest.of(page, size,
            Sort.by(Sort.Direction.DESC, "createdAt"));

        Page<PolicyResponse> result = policyService.search(framework, category, status, name, pageable);

        return ResponseEntity.ok()
            .header("Cache-Control", "max-age=60, must-revalidate")
            .body(result);
    }

    @GetMapping("/{id}")
    @Operation(
        summary = "Obtener política por ID",
        description = "Retorna todos los atributos de una política. Operación de solo lectura e idempotente."
    )
    public ResponseEntity<PolicyResponse> getById(@PathVariable UUID id) {
        PolicyResponse policy = policyService.findById(id);
        return ResponseEntity.ok()
            .eTag(String.valueOf(policy.version()))
            .body(policy);
    }

    @GetMapping("/{id}/traceability")
    @Operation(
        summary = "Trazabilidad de una política",
        description = "El control del Anexo A de ISO/IEC 27001 y, cuando existe, la guía de implementación " +
            "de ISO/IEC 27002 correspondiente. Accesible para todos los roles autenticados."
    )
    public PolicyTraceabilityResponse traceability(@PathVariable UUID id) {
        return policyService.getTraceability(id);
    }

    @GetMapping("/{id}/audit-log")
    @Operation(
        summary = "Historial de cambios de una política",
        description = "Quién creó, editó, archivó o restauró la política, con su id de usuario, cuándo, y qué " +
            "cambió en cada paso. Accesible para todos los roles autenticados (útil para el rol AUDITOR)."
    )
    public List<PolicyAuditLogEntryResponse> auditLog(@PathVariable UUID id) {
        return policyService.getAuditLog(id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Registrar política de seguridad",
        description = "Crea una política alineada a un marco normativo. Requiere rol SECURITY_ADMIN."
    )
    public PolicyResponse create(
            @Valid @RequestBody CreatePolicyRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        return policyService.create(request, userDetails.getUsername());
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Actualizar política",
        description = "Actualiza description, weight y/o applicability. framework, controlId y category son " +
            "inmutables. El header If-Match (versión actual) es opcional pero recomendado: si se envía y no " +
            "coincide con la versión vigente, se rechaza con HTTP 412. Requiere rol SECURITY_ADMIN."
    )
    public ResponseEntity<PolicyResponse> patch(
            @PathVariable UUID id,
            @Valid @RequestBody UpdatePolicyRequest request,
            @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @AuthenticationPrincipal UserDetails userDetails) {
        Integer ifMatchVersion = parseIfMatch(ifMatch);
        PolicyResponse updated = policyService.patch(id, request, ifMatchVersion, userDetails.getUsername());
        return ResponseEntity.ok()
            .eTag(String.valueOf(updated.version()))
            .body(updated);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Archivar política",
        description = "Archivado lógico (nunca elimina físicamente). Rechaza con HTTP 409 si existen análisis " +
            "QUEUED o RUNNING que dependan de la política. Requiere rol SECURITY_ADMIN."
    )
    public void archive(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {
        policyService.archive(id, userDetails.getUsername());
    }

    @PostMapping("/{id}/restore")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Restaurar política archivada",
        description = "Cambia el estado de ARCHIVED a ACTIVE. Requiere rol SECURITY_ADMIN."
    )
    public PolicyResponse restore(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {
        return policyService.restore(id, userDetails.getUsername());
    }

    private Integer parseIfMatch(String ifMatch) {
        if (!StringUtils.hasText(ifMatch)) {
            return null;
        }
        String cleaned = ifMatch.replace("\"", "").trim();
        try {
            return Integer.parseInt(cleaned);
        } catch (NumberFormatException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Header If-Match inválido");
        }
    }
}
