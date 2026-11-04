package co.icesi.pdgseg.exception;

/**
 * A rejected login (unknown user, wrong password or disabled account) whose message also warns
 * about the lock; unlike a plain {@link AuthException}, the message goes to the client as is.
 */
public class InvalidLoginException extends AuthException {

    /** Attempts left before the lock, or null when the account is not known to the caller. */
    private final Integer attemptsLeft;

    public InvalidLoginException(String message, Integer attemptsLeft) {
        super(message);
        this.attemptsLeft = attemptsLeft;
    }

    public Integer getAttemptsLeft() {
        return attemptsLeft;
    }
}
