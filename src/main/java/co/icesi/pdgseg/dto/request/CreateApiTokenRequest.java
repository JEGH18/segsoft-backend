package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @param expiresInDays days until the token stops working; {@code null} means
 *                      {@link #DEFAULT_EXPIRES_IN_DAYS}
 */
public record CreateApiTokenRequest(
    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 150, message = "El nombre no puede superar 150 caracteres")
    String name,

    @Min(value = 1, message = "El token debe durar al menos 1 día")
    @Max(value = 365, message = "El token puede durar como máximo 365 días")
    Integer expiresInDays
) {
    public static final int DEFAULT_EXPIRES_IN_DAYS = 90;

    public int expiresInDaysOrDefault() {
        return expiresInDays != null ? expiresInDays : DEFAULT_EXPIRES_IN_DAYS;
    }
}
