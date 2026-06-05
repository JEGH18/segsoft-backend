package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.UUID;

public record PolicySelectionRequest(
        @NotEmpty List<@NotNull UUID> policyIds
) {
}
