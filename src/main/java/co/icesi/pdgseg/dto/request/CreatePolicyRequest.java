package co.icesi.pdgseg.dto.request;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CreatePolicyRequest(

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 200, message = "El nombre no puede superar 200 caracteres")
    String name,

    @NotBlank(message = "La descripción es obligatoria")
    @Size(min = 20, max = 500, message = "La descripción debe tener entre 20 y 500 caracteres")
    String description,

    @NotNull(message = "La categoría es obligatoria")
    Category category,

    @NotNull(message = "El marco normativo es obligatorio")
    Framework framework,

    @Size(max = 100, message = "El control_id no puede superar 100 caracteres")
    String controlId,

    // Solo aplica para framework=ISO_27001. Opcional: si se omite, la
    // política queda con detailPending=true hasta completarse vía PATCH.
    @Size(max = 20, message = "El implementationGuideId no puede superar 20 caracteres")
    String implementationGuideId
) {
    // Convenience overload for callers that don't care about implementationGuideId.
    public CreatePolicyRequest(String name, String description, Category category,
                                Framework framework, String controlId) {
        this(name, description, category, framework, controlId, null);
    }
}
