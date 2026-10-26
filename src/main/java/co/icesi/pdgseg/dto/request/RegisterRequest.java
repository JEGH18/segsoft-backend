package co.icesi.pdgseg.dto.request;

import co.icesi.pdgseg.security.PasswordConstraint;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RegisterRequest(
        @NotBlank(message = "El usuario es requerido")
        @Pattern(regexp = "^\\s*[A-Za-z][A-Za-z0-9._-]{2,49}\\s*$",
                 message = "El usuario debe tener entre 3 y 50 caracteres, empezar por una letra y "
                         + "usar solo letras, números, '.', '_' o '-'")
        String username,

        @PasswordConstraint
        String password
) {}
