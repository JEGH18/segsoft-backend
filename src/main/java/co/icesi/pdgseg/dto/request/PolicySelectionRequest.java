package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.UUID;

/**
 * policySetId is optional and purely for traceability: when present, the
 * service records that this selection was populated by applying that Policy
 * Set (needed to block archiving it while an analysis is in flight). The
 * actual policyIds are always a plain snapshot copy taken at apply time --
 * editing the Policy Set afterward never retroactively changes an existing
 * selection. Sending policyIds without policySetId (or omitting it) is a
 * manual selection and clears any previous link.
 */
public record PolicySelectionRequest(
        @NotEmpty List<@NotNull UUID> policyIds,
        UUID policySetId
) {
}
