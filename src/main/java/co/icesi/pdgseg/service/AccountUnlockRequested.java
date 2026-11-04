package co.icesi.pdgseg.service;

/**
 * Published when an account is locked and has a verified email; {@link AuthMailer} sends the unlock
 * link once the login's transaction commits. {@code token} is the only copy of the raw token.
 */
public record AccountUnlockRequested(String username, String email, String token,
                                     int failedAttempts, long lockMinutes) {

    @Override
    public String toString() {
        return "AccountUnlockRequested[username=" + username + "]";
    }
}
