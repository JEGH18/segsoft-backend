package co.icesi.pdgseg.dto.request;

import co.icesi.pdgseg.security.PasswordConstraint;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank(message = "El token es requerido")
        @Size(max = 200, message = "El token no es válido")
        String token,

        @PasswordConstraint
        String password
) {}
