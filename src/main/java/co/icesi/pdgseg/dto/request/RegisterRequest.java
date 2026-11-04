package co.icesi.pdgseg.dto.request;

import co.icesi.pdgseg.security.PasswordConstraint;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "El usuario es requerido")
        @Pattern(regexp = "^\\s*[A-Za-z][A-Za-z0-9._-]{2,49}\\s*$",
                 message = "El usuario debe tener entre 3 y 50 caracteres, empezar por una letra y "
                         + "usar solo letras, números, '.', '_' o '-'")
        String username,

        @NotBlank(message = "El correo es requerido")
        @Size(max = 254, message = "El correo no puede tener más de 254 caracteres")
        @Pattern(regexp = RegisterRequest.EMAIL_PATTERN, message = "El correo no es válido")
        String email,

        @PasswordConstraint
        String password
) {
    /** One "@", no spaces inside, and a dot in the domain; surrounding spaces are trimmed later. */
    public static final String EMAIL_PATTERN = "^\\s*[^@\\s]+@[^@\\s]+\\.[^@\\s]+\\s*$";
}
