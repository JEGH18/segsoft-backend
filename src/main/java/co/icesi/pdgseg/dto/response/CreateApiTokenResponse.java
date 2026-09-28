package co.icesi.pdgseg.dto.response;

import java.time.OffsetDateTime;
import java.util.UUID;

/** The plaintext token is only ever present in this one response, at creation time. */
public record CreateApiTokenResponse(
    UUID id,
    String name,
    String token,
    OffsetDateTime createdAt
) {}
