package co.icesi.pdgseg.dto.response;

/** A new account waits for its email to be verified, so registering does not start a session. */
public record RegistrationResponse(
        String username,
        String email,
        String message
) {}
