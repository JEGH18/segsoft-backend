package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.response.FileInventoryResponse;
import co.icesi.pdgseg.dto.response.RepositoryFileResponse;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.enums.ArtifactType;
import co.icesi.pdgseg.entity.enums.InventoryStatus;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.RepositoryFileRepository;
import co.icesi.pdgseg.repository.RepositoryRepository;
import co.icesi.pdgseg.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/repositories/{repoId}/files")
@Tag(name = "Repository Files", description = "Inventario de archivos del repositorio cargado")
public class RepositoryFileController {

    private final RepositoryRepository repositoryRepository;
    private final RepositoryFileRepository repositoryFileRepository;
    private final UserRepository userRepository;

    public RepositoryFileController(RepositoryRepository repositoryRepository,
                                    RepositoryFileRepository repositoryFileRepository,
                                    UserRepository userRepository) {
        this.repositoryRepository = repositoryRepository;
        this.repositoryFileRepository = repositoryFileRepository;
        this.userRepository = userRepository;
    }

    @GetMapping
    @Operation(summary = "Listar archivos inventariados del repositorio",
            description = "Retorna los archivos del repositorio agrupados con metadatos. "
                    + "Devuelve HTTP 202 si el inventario aún está en progreso.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Inventario disponible"),
            @ApiResponse(responseCode = "202", description = "Inventario en progreso"),
            @ApiResponse(responseCode = "403", description = "Sin permisos sobre este repositorio"),
            @ApiResponse(responseCode = "404", description = "Repositorio no encontrado")
    })
    public ResponseEntity<FileInventoryResponse> listFiles(
            @PathVariable UUID repoId,
            @Parameter(description = "Filtrar por lenguaje (ej. java, python, javascript)")
            @RequestParam(required = false) String language,
            @Parameter(description = "Filtrar por tipo de artefacto")
            @RequestParam(required = false) String artifactType,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            Authentication authentication
    ) {
        Repository repo = repositoryRepository.findById(repoId)
                .orElseThrow(() -> new ResourceNotFoundException("Repository not found: " + repoId));

        checkAccess(repo, authentication);

        if (repo.getInventoryStatus() == InventoryStatus.INVENTORYING
                || repo.getInventoryStatus() == InventoryStatus.PENDING) {
            FileInventoryResponse body = new FileInventoryResponse(
                    repoId,
                    repo.getInventoryStatus(),
                    0, 0,
                    Map.of(), Map.of(),
                    page, size, 0, 0,
                    List.of()
            );
            return ResponseEntity.accepted().body(body);
        }

        ArtifactType artifactTypeEnum = parseArtifactType(artifactType);
        Pageable pageable = PageRequest.of(page, Math.min(size, 100), Sort.by("path").ascending());

        Page<RepositoryFileResponse> filePage = repositoryFileRepository
                .findByFilters(repoId, language, artifactTypeEnum, pageable)
                .map(RepositoryFileResponse::from);

        Map<String, Long> byLanguage = buildLanguageMap(repoId);
        Map<String, Long> byArtifactType = buildArtifactTypeMap(repoId);
        long totalFiles = repositoryFileRepository.countByRepositoryId(repoId);

        FileInventoryResponse response = new FileInventoryResponse(
                repoId,
                repo.getInventoryStatus(),
                totalFiles,
                repo.getExcludedCount(),
                byLanguage,
                byArtifactType,
                filePage.getNumber(),
                filePage.getSize(),
                filePage.getTotalElements(),
                filePage.getTotalPages(),
                filePage.getContent()
        );

        return ResponseEntity.ok(response);
    }

    private void checkAccess(Repository repo, Authentication authentication) {
        boolean isPrivileged = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(a -> a.equals("ROLE_AUDITOR") || a.equals("ROLE_SECURITY_ADMIN"));

        if (isPrivileged) return;

        var user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new AccessDeniedException("Usuario no autenticado"));
        if (!user.getId().equals(repo.getUserId())) {
            throw new AccessDeniedException("No tiene acceso a este repositorio");
        }
    }

    private ArtifactType parseArtifactType(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            return ArtifactType.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private Map<String, Long> buildLanguageMap(UUID repoId) {
        Map<String, Long> map = new LinkedHashMap<>();
        repositoryFileRepository.countGroupedByLanguage(repoId)
                .forEach(row -> map.put((String) row[0], (Long) row[1]));
        return map;
    }

    private Map<String, Long> buildArtifactTypeMap(UUID repoId) {
        Map<String, Long> map = new LinkedHashMap<>();
        repositoryFileRepository.countGroupedByArtifactType(repoId)
                .forEach(row -> map.put(((ArtifactType) row[0]).name(), (Long) row[1]));
        return map;
    }
}
