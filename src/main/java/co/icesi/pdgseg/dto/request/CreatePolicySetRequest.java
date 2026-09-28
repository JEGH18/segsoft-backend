package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

public record CreatePolicySetRequest(

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 200, message = "El nombre no puede superar 200 caracteres")
    String name,

    @Size(max = 1000, message = "La descripción no puede superar 1000 caracteres")
    String description,

    @NotEmpty(message = "Debe incluir al menos una política")
    List<UUID> policyIds
) {}
