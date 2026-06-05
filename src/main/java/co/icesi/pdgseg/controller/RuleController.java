package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.CreateRuleRequest;
import co.icesi.pdgseg.dto.response.RuleResponse;
import co.icesi.pdgseg.service.RuleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@Tag(name = "Reglas", description = "Gestión de reglas técnicas verificables por política")
@SecurityRequirement(name = "bearerAuth")
public class RuleController {

    private final RuleService ruleService;

    public RuleController(RuleService ruleService) {
        this.ruleService = ruleService;
    }

    @PostMapping("/api/v1/policies/{policyId}/rules")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(summary = "Crear regla técnica",
               description = "Asocia una regla verificable a una política. Requiere SECURITY_ADMIN.")
    public RuleResponse create(@PathVariable UUID policyId,
                               @Valid @RequestBody CreateRuleRequest request) {
        return ruleService.create(policyId, request);
    }

    @GetMapping("/api/v1/policies/{policyId}/rules")
    @Operation(summary = "Listar reglas de una política")
    public Page<RuleResponse> listByPolicy(
            @PathVariable UUID policyId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ruleService.listByPolicy(policyId,
            PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    @DeleteMapping("/api/v1/rules/{ruleId}")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    @Operation(summary = "Archivar regla (eliminación lógica)",
               description = "Cambia el estado de la regla a ARCHIVED preservando trazabilidad histórica.")
    public RuleResponse archive(@PathVariable UUID ruleId) {
        return ruleService.archive(ruleId);
    }
}
