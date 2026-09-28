package co.icesi.pdgseg.dto.request;

import jakarta.validation.constraints.Size;

import java.util.Map;

/**
 * Only description, weight, and applicability are editable via PATCH.
 * name/framework/controlId/category are accepted here purely for detection —
 * if the client sends any of framework/controlId/category, the service
 * rejects the request with HTTP 400 rather than silently ignoring them.
 */
public record UpdatePolicyRequest(
    @Size(min = 20, max = 500, message = "La descripción debe tener entre 20 y 500 caracteres")
    String description,

    Integer weight,
    Map<String, Object> applicability,
    String framework,
    String controlId,
    String category,

    // Editable, unlike controlId: this is precisely how a policy registered
    // before this feature (detailPending=true) gets its ISO/IEC 27002 detail
    // completed later, without needing to recreate the policy.
    @Size(max = 20, message = "El implementationGuideId no puede superar 20 caracteres")
    String implementationGuideId
) {
    // Convenience overload for callers that don't care about implementationGuideId.
    public UpdatePolicyRequest(String description, Integer weight, Map<String, Object> applicability,
                                String framework, String controlId, String category) {
        this(description, weight, applicability, framework, controlId, category, null);
    }

    public boolean touchesImmutableFields() {
        return framework != null || controlId != null || category != null;
    }
}
