package co.icesi.pdgseg.dto.response;

import java.time.OffsetDateTime;
import java.util.UUID;

/** Metadata only -- never carries the token value itself. */
public record ApiTokenResponse(
    UUID id,
    String name,
    OffsetDateTime createdAt,
    UUID createdById
) {}
