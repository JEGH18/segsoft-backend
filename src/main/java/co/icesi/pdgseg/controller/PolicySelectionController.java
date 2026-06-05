package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.PolicySelectionRequest;
import co.icesi.pdgseg.dto.response.PolicySelectionResponse;
import co.icesi.pdgseg.service.PolicySelectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/repositories/{repoId}/policy-selection")
@Tag(name = "Selección de políticas", description = "Gestiona el conjunto de políticas a evaluar por repositorio")
public class PolicySelectionController {

    private final PolicySelectionService policySelectionService;

    public PolicySelectionController(PolicySelectionService policySelectionService) {
        this.policySelectionService = policySelectionService;
    }

    @PostMapping
    @PreAuthorize("@repositoryAuthorizationService.canModify(#repoId, authentication)")
    @Operation(summary = "Crear selección de políticas")
    public ResponseEntity<PolicySelectionResponse> createSelection(@PathVariable UUID repoId,
                                                                   @Valid @RequestBody PolicySelectionRequest request,
                                                                   @AuthenticationPrincipal UserDetails userDetails) {
        PolicySelectionResponse response =
                policySelectionService.createSelection(repoId, request, userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PutMapping
    @PreAuthorize("@repositoryAuthorizationService.canModify(#repoId, authentication)")
    @Operation(summary = "Actualizar selección de políticas")
    public ResponseEntity<PolicySelectionResponse> updateSelection(@PathVariable UUID repoId,
                                                                   @Valid @RequestBody PolicySelectionRequest request,
                                                                   @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(policySelectionService.updateSelection(repoId, request, userDetails.getUsername()));
    }

    @GetMapping
    @PreAuthorize("@repositoryAuthorizationService.canRead(#repoId, authentication)")
    @Operation(summary = "Obtener selección de políticas")
    public ResponseEntity<PolicySelectionResponse> getSelection(@PathVariable UUID repoId) {
        return ResponseEntity.ok(policySelectionService.getSelection(repoId));
    }

    @DeleteMapping
    @PreAuthorize("@repositoryAuthorizationService.canModify(#repoId, authentication)")
    @Operation(summary = "Eliminar selección de políticas")
    public ResponseEntity<Void> deleteSelection(@PathVariable UUID repoId) {
        policySelectionService.deleteSelection(repoId);
        return ResponseEntity.noContent().build();
    }
}
