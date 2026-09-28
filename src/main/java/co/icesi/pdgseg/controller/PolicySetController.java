package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.CreatePolicySetRequest;
import co.icesi.pdgseg.dto.request.UpdatePolicySetRequest;
import co.icesi.pdgseg.dto.response.PolicyAuditLogEntryResponse;
import co.icesi.pdgseg.dto.response.PolicySetDetailResponse;
import co.icesi.pdgseg.dto.response.PolicySetPageResponse;
import co.icesi.pdgseg.dto.response.PolicySetResponse;
import co.icesi.pdgseg.entity.enums.PolicySetStatus;
import co.icesi.pdgseg.service.PolicySetService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/policy-sets")
@Tag(name = "Policy Sets", description = "Conjuntos reutilizables de políticas activas del banco, para estandarizar perfiles de cumplimiento")
@SecurityRequirement(name = "bearerAuth")
public class PolicySetController {

    private final PolicySetService policySetService;

    public PolicySetController(PolicySetService policySetService) {
        this.policySetService = policySetService;
    }

    @GetMapping
    @Operation(
        summary = "Listar Policy Sets",
        description = "Listado paginado. Por defecto solo retorna los ACTIVE (los archivados desaparecen " +
            "del listado); filtrable por status y por nombre (search, insensible a mayúsculas/minúsculas). " +
            "Accesible para todos los roles autenticados."
    )
    public PolicySetPageResponse list(
            @RequestParam(required = false) PolicySetStatus status,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        if (size > 100) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El tamaño máximo de página es 100");
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        return policySetService.list(status, search, pageable);
    }

    @GetMapping("/{id}")
    @Operation(
        summary = "Obtener el detalle de un Policy Set",
        description = "Incluye las políticas incluidas (id, name, framework, category), la cobertura por " +
            "las 5 categorías de Claude Code Security y el número de repositorios donde se ha aplicado."
    )
    public PolicySetDetailResponse getById(@PathVariable UUID id) {
        return policySetService.findDetailById(id);
    }

    @GetMapping("/{id}/audit-log")
    @Operation(summary = "Historial de cambios de un Policy Set")
    public List<PolicyAuditLogEntryResponse> auditLog(@PathVariable UUID id) {
        return policySetService.getAuditLog(id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Crear Policy Set",
        description = "Agrupa políticas ACTIVE del banco bajo un nombre y descripción. Rechaza con HTTP 400 " +
            "si algún policyId no existe o no está ACTIVE. Requiere rol SECURITY_ADMIN."
    )
    public PolicySetResponse create(
            @Valid @RequestBody CreatePolicySetRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        return policySetService.create(request, userDetails.getUsername());
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Editar Policy Set",
        description = "Actualiza nombre, descripción y/o composición (policyIds reemplaza la lista completa). " +
            "Incrementa version en 1 y registra el diff en auditoría. No afecta retroactivamente repositorios " +
            "donde el set ya se aplicó. Requiere rol SECURITY_ADMIN."
    )
    public PolicySetResponse patch(
            @PathVariable UUID id,
            @Valid @RequestBody UpdatePolicySetRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        return policySetService.patch(id, request, userDetails.getUsername());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Archivar Policy Set",
        description = "Archivado lógico (nunca elimina físicamente). Rechaza con HTTP 409 si existen análisis " +
            "QUEUED o RUNNING sobre un repositorio donde este Policy Set ya se aplicó. Requiere rol SECURITY_ADMIN."
    )
    public void archive(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {
        policySetService.archive(id, userDetails.getUsername());
    }

    @PostMapping("/{id}/restore")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(
        summary = "Restaurar Policy Set archivado",
        description = "Cambia el estado de ARCHIVED a ACTIVE; vuelve a quedar disponible para aplicarse a repositorios de inmediato. Requiere rol SECURITY_ADMIN."
    )
    public PolicySetResponse restore(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {
        return policySetService.restore(id, userDetails.getUsername());
    }
}
