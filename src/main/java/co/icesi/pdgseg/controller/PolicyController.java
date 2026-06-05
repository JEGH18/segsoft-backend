package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.CreatePolicyRequest;
import co.icesi.pdgseg.dto.response.CategoryCoverageItem;
import co.icesi.pdgseg.dto.response.PolicyResponse;
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
    public PolicyResponse getById(@PathVariable UUID id) {
        return policyService.findById(id);
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
}
