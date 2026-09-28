package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.CreateApiTokenRequest;
import co.icesi.pdgseg.dto.response.ApiTokenResponse;
import co.icesi.pdgseg.dto.response.CreateApiTokenResponse;
import co.icesi.pdgseg.service.ApiTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth/api-tokens")
@Tag(name = "Tokens de API", description = "Tokens de larga duración para pipelines CI/CD, distintos del JWT de sesión web")
@SecurityRequirement(name = "bearerAuth")
@PreAuthorize("hasRole('SECURITY_ADMIN')")
public class ApiTokenController {

    private final ApiTokenService apiTokenService;

    public ApiTokenController(ApiTokenService apiTokenService) {
        this.apiTokenService = apiTokenService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Crear token de API",
        description = "Genera un token de larga duración para CI/CD. El valor en claro solo se devuelve en esta " +
            "respuesta; en el servidor únicamente se almacena su hash. Requiere rol SECURITY_ADMIN."
    )
    public CreateApiTokenResponse create(
            @Valid @RequestBody CreateApiTokenRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        return apiTokenService.create(request, userDetails.getUsername());
    }

    @GetMapping
    @Operation(
        summary = "Listar tokens de API",
        description = "Retorna solo metadatos (id, nombre, fecha de creación) -- nunca el valor del token. " +
            "Requiere rol SECURITY_ADMIN."
    )
    public List<ApiTokenResponse> list() {
        return apiTokenService.list();
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
        summary = "Revocar token de API",
        description = "Elimina el token; cualquier pipeline que lo use deja de poder autenticarse de inmediato. " +
            "Requiere rol SECURITY_ADMIN."
    )
    public void revoke(@PathVariable UUID id) {
        apiTokenService.revoke(id);
    }
}
