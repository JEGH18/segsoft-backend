package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.CloneRepositoryRequest;
import co.icesi.pdgseg.dto.response.RepositoryResponse;
import co.icesi.pdgseg.service.FileInventoryService;
import co.icesi.pdgseg.service.RepositoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/repositories")
@Tag(name = "Repositories", description = "Carga de repositorios para análisis")
@SecurityRequirement(name = "bearerAuth")
public class RepositoryController {

    private final RepositoryService repositoryService;
    private final FileInventoryService fileInventoryService;

    public RepositoryController(RepositoryService repositoryService,
                                 FileInventoryService fileInventoryService) {
        this.repositoryService = repositoryService;
        this.fileInventoryService = fileInventoryService;
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Cargar repositorio mediante archivo ZIP")
    public ResponseEntity<RepositoryResponse> uploadZip(
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserDetails userDetails) {

        RepositoryResponse response = repositoryService.uploadZip(file, userDetails.getUsername());
        fileInventoryService.triggerInventory(response.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping(value = "/git", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Cargar repositorio mediante URL Git")
    public ResponseEntity<RepositoryResponse> cloneGit(
            @Valid @RequestBody CloneRepositoryRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {

        RepositoryResponse response = repositoryService.cloneGit(
                request.getGitUrl(), request.getBranch(), userDetails.getUsername());
        fileInventoryService.triggerInventory(response.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Consultar estado de un repositorio")
    public ResponseEntity<RepositoryResponse> getRepository(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {

        return ResponseEntity.ok(repositoryService.findById(id, userDetails.getUsername()));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Eliminar repositorio y su sandbox")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public ResponseEntity<Void> deleteRepository(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {

        repositoryService.delete(id, userDetails.getUsername());
        return ResponseEntity.noContent().build();
    }
}
