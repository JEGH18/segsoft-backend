package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record ApplyPolicySetRequest(
        @NotNull UUID policySetId
) {
}
