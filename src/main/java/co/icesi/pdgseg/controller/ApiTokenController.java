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
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Every authenticated user manages their own tokens; a SECURITY_ADMIN sees and revokes everyone's.
 * Requests authenticated with an API token are rejected here by JwtAuthenticationFilter.
 */
@RestController
@RequestMapping("/api/v1/auth/api-tokens")
@Tag(name = "Tokens de API", description = "Tokens de larga duración para pipelines CI/CD, distintos del JWT de sesión web")
@SecurityRequirement(name = "bearerAuth")
public class ApiTokenController {

    private final ApiTokenService apiTokenService;

    public ApiTokenController(ApiTokenService apiTokenService) {
        this.apiTokenService = apiTokenService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Crear token de API",
        description = "Genera un token para CI/CD que autentica como el usuario que lo crea, con sus mismos roles. " +
            "El valor en claro solo se devuelve en esta respuesta; en el servidor únicamente se guarda su hash. " +
            "Vence a los expiresInDays días (1 a 365, por defecto 90). Máximo 10 tokens vigentes por usuario (409). " +
            "Se usa como 'Authorization: Bearer pdgseg_...'."
    )
    public CreateApiTokenResponse create(@Valid @RequestBody CreateApiTokenRequest request,
                                         Authentication authentication) {
        return apiTokenService.create(request, authentication.getName());
    }

    @GetMapping
    @Operation(
        summary = "Listar tokens de API",
        description = "Retorna solo metadatos (nombre, prefijo, dueño, creación, vencimiento y último uso), nunca " +
            "el valor del token. Cada usuario ve los suyos; un SECURITY_ADMIN ve los de todos."
    )
    public List<ApiTokenResponse> list(Authentication authentication) {
        return apiTokenService.list(authentication.getName(), isSecurityAdmin(authentication));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
        summary = "Revocar token de API",
        description = "Elimina el token; cualquier pipeline que lo use deja de autenticarse de inmediato. " +
            "Cada usuario revoca los suyos; un SECURITY_ADMIN, cualquiera. 404 si no existe o es de otro usuario."
    )
    public void revoke(@PathVariable UUID id, Authentication authentication) {
        apiTokenService.revoke(id, authentication.getName(), isSecurityAdmin(authentication));
    }

    private static boolean isSecurityAdmin(Authentication authentication) {
        return authentication.getAuthorities().stream()
            .anyMatch(a -> "ROLE_SECURITY_ADMIN".equals(a.getAuthority()));
    }
}
