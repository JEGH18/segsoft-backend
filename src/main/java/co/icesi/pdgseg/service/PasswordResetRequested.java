package co.icesi.pdgseg.service;

/**
 * Published when someone asks to reset the password of an account with a verified email;
 * {@link AuthMailer} sends the link once the transaction commits. {@code token} is the only copy of
 * the raw token.
 */
public record PasswordResetRequested(String username, String email, String token, long validMinutes) {

    @Override
    public String toString() {
        return "PasswordResetRequested[username=" + username + "]";
    }
}
