package co.icesi.pdgseg.dto.response;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

/** One entry of a policy's change history -- who did what, and when. */
public record PolicyAuditLogEntryResponse(
    UUID id,
    String action,
    UUID userId,
    String username,
    OffsetDateTime timestamp,
    Map<String, Object> payload
) {}
