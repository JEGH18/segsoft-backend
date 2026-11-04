package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ResendVerificationRequest(
        @NotBlank(message = "El correo es requerido")
        @Size(max = 254, message = "El correo no puede tener más de 254 caracteres")
        @Pattern(regexp = RegisterRequest.EMAIL_PATTERN, message = "El correo no es válido")
        String email
) {}
