package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.LoginRequest;
import co.icesi.pdgseg.dto.request.RegisterRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.dto.response.UserResponse;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.service.AuthService;
import co.icesi.pdgseg.service.RegistrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Autenticación", description = "Endpoints de autenticación y gestión de sesión JWT")
public class AuthController {

    private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    @Value("${jwt.refresh-token-expiration-ms:28800000}")
    private long refreshTokenExpirationMs;

    @Value("${auth.cookie.secure:true}")
    private boolean cookieSecure;

    private final AuthService authService;
    private final RegistrationService registrationService;

    public AuthController(AuthService authService, RegistrationService registrationService) {
        this.authService = authService;
        this.registrationService = registrationService;
    }

    @PostMapping("/register")
    @Operation(summary = "Registrar una cuenta",
               description = "Crea una cuenta con rol DEVELOPER e inicia su sesión: retorna accessToken en body y "
                       + "refreshToken en cookie httpOnly. 409 si el usuario ya existe, 403 si el registro está "
                       + "deshabilitado y 429 si se supera el límite de registros.")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request,
                                                 HttpServletRequest httpRequest,
                                                 HttpServletResponse httpResponse) {
        AuthResponse auth = registrationService.register(request, resolveIp(httpRequest));
        setRefreshTokenCookie(auth.refreshToken(), httpResponse);
        return ResponseEntity.status(HttpStatus.CREATED).body(auth);
    }

    @GetMapping("/registration")
    @Operation(summary = "Estado del registro",
               description = "Indica si se pueden crear cuentas nuevas desde la aplicación.")
    public ResponseEntity<Map<String, Boolean>> registrationStatus() {
        return ResponseEntity.ok(Map.of("enabled", registrationService.isEnabled()));
    }

    @PostMapping("/login")
    @Operation(summary = "Autenticar usuario",
               description = "Autentica con usuario y contraseña. Retorna accessToken en body y refreshToken en cookie httpOnly.")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
                                              HttpServletRequest httpRequest,
                                              HttpServletResponse httpResponse) {
        String ipAddress = resolveIp(httpRequest);
        AuthResponse auth = authService.login(request, ipAddress);
        setRefreshTokenCookie(auth.refreshToken(), httpResponse);
        return ResponseEntity.ok(auth);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Renovar accessToken",
               description = "Valida el refreshToken de la cookie, lo rota y emite un nuevo accessToken.")
    public ResponseEntity<AuthResponse> refresh(
            @CookieValue(name = REFRESH_TOKEN_COOKIE, required = false) String refreshToken,
            HttpServletResponse httpResponse) {
        if (!StringUtils.hasText(refreshToken)) {
            throw new AuthException("Credenciales inválidas");
        }
        AuthResponse auth = authService.refresh(refreshToken);
        setRefreshTokenCookie(auth.refreshToken(), httpResponse);
        return ResponseEntity.ok(auth);
    }

    @PostMapping("/logout")
    @Operation(summary = "Cerrar sesión",
               description = "Invalida el refreshToken y limpia la cookie.")
    public ResponseEntity<Void> logout(
            @CookieValue(name = REFRESH_TOKEN_COOKIE, required = false) String refreshToken,
            HttpServletResponse httpResponse) {
        if (StringUtils.hasText(refreshToken)) {
            authService.logout(refreshToken);
        }
        clearRefreshTokenCookie(httpResponse);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    @SecurityRequirement(name = "BearerAuth")
    @Operation(summary = "Usuario actual",
               description = "Retorna los datos del usuario autenticado. Requiere rol: cualquier rol válido.")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(authService.getCurrentUser(userDetails.getUsername()));
    }

    private void setRefreshTokenCookie(String token, HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, token)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/api/v1/auth")
                .maxAge(Duration.ofMillis(refreshTokenExpirationMs))
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/api/v1/auth")
                .maxAge(Duration.ZERO)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private String resolveIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwarded)) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
