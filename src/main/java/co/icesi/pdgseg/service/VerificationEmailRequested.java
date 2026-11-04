package co.icesi.pdgseg.service;

/**
 * Published when a verification link is issued; {@link VerificationMailer} sends it once the
 * transaction that stored the link commits. {@code token} is the only copy of the raw token.
 */
public record VerificationEmailRequested(String username, String email, String token) {

    @Override
    public String toString() {
        return "VerificationEmailRequested[username=" + username + "]";
    }
}
