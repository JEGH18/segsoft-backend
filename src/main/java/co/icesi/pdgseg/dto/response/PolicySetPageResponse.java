package co.icesi.pdgseg.dto.response;

import java.util.List;

/**
 * GET /api/v1/policy-sets. A bare Spring Data Page<> has no room for the
 * "catalog is genuinely empty, go create one" message escenario 4 asks
 * for, so this wraps it with one extra field instead.
 */
public record PolicySetPageResponse(
    List<PolicySetResponse> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    String message
) {}
