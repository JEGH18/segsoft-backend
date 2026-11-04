package co.icesi.pdgseg.exception;

/** Too many failed logins: the account is locked for a while, whatever the password. */
public class AccountLockedException extends RuntimeException {

    private final long minutesLeft;

    public AccountLockedException(String message, long minutesLeft) {
        super(message);
        this.minutesLeft = minutesLeft;
    }

    public long getMinutesLeft() {
        return minutesLeft;
    }
}
