package co.icesi.pdgseg.dto.response;

import java.util.List;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String username,
        /* Null for the deployment accounts, which have no email. */
        String email,
        List<String> roles
) {}
