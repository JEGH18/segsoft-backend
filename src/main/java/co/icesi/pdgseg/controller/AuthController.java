package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.dto.request.LoginRequest;
import co.icesi.pdgseg.dto.request.RegisterRequest;
import co.icesi.pdgseg.dto.request.ResendVerificationRequest;
import co.icesi.pdgseg.dto.request.UnlockAccountRequest;
import co.icesi.pdgseg.dto.request.VerifyEmailRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.dto.response.RegistrationResponse;
import co.icesi.pdgseg.dto.response.UserResponse;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.service.AccountUnlockService;
import co.icesi.pdgseg.service.AuthService;
import co.icesi.pdgseg.service.EmailVerificationService;
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
    private final EmailVerificationService emailVerificationService;
    private final AccountUnlockService accountUnlockService;

    public AuthController(AuthService authService,
                          RegistrationService registrationService,
                          EmailVerificationService emailVerificationService,
                          AccountUnlockService accountUnlockService) {
        this.authService = authService;
        this.registrationService = registrationService;
        this.emailVerificationService = emailVerificationService;
        this.accountUnlockService = accountUnlockService;
    }

    @PostMapping("/register")
    @Operation(summary = "Registrar una cuenta",
               description = "Crea una cuenta con rol DEVELOPER y le envía al correo un enlace de verificación. "
                       + "No inicia sesión: la cuenta no puede entrar hasta verificar el correo. 409 si el usuario "
                       + "o el correo ya existen, 403 si el registro está deshabilitado, 429 si se supera el "
                       + "límite de registros y 503 si el envío de correos no está configurado.")
    public ResponseEntity<RegistrationResponse> register(@Valid @RequestBody RegisterRequest request,
                                                         HttpServletRequest httpRequest) {
        RegistrationResponse registration = registrationService.register(request, resolveIp(httpRequest));
        return ResponseEntity.status(HttpStatus.CREATED).body(registration);
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Verificar el correo",
               description = "Consume el token del enlace enviado por correo, marca el correo como verificado e "
                       + "inicia la sesión (accessToken en body y refreshToken en cookie httpOnly). Es POST para "
                       + "que los antivirus y las vistas previas de los correos, que abren los enlaces con GET, "
                       + "no gasten el token. 400 si el token no es válido, ya se usó o venció.")
    public ResponseEntity<AuthResponse> verifyEmail(@Valid @RequestBody VerifyEmailRequest request,
                                                    HttpServletRequest httpRequest,
                                                    HttpServletResponse httpResponse) {
        AuthResponse auth = emailVerificationService.verify(request.token(), resolveIp(httpRequest));
        setRefreshTokenCookie(auth.refreshToken(), httpResponse);
        return ResponseEntity.ok(auth);
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Reenviar el enlace de verificación",
               description = "Envía un enlace nuevo si el correo pertenece a una cuenta sin verificar e invalida "
                       + "los anteriores. Responde 202 exista o no la cuenta.")
    public ResponseEntity<Map<String, String>> resendVerification(@Valid @RequestBody ResendVerificationRequest request,
                                                                  HttpServletRequest httpRequest) {
        emailVerificationService.resend(request.email(), resolveIp(httpRequest));
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("message",
                "Si el correo pertenece a una cuenta sin verificar, te enviamos un enlace nuevo."));
    }

    @PostMapping("/unlock")
    @Operation(summary = "Desbloquear una cuenta",
               description = "Consume el token del enlace que se envía al correo verificado de una cuenta cuando se "
                       + "bloquea por intentos fallidos, y levanta el bloqueo. No inicia sesión: después hay que "
                       + "entrar con la contraseña. 400 si el token no es válido, ya se usó o venció.")
    public ResponseEntity<Map<String, String>> unlock(@Valid @RequestBody UnlockAccountRequest request,
                                                      HttpServletRequest httpRequest) {
        accountUnlockService.unlock(request.token(), resolveIp(httpRequest));
        return ResponseEntity.ok(Map.of("message", "Tu cuenta quedó desbloqueada. Ya puedes iniciar sesión."));
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
