package co.icesi.pdgseg.exception;

public class InvalidVerificationTokenException extends RuntimeException {
    public InvalidVerificationTokenException() {
        this("El enlace de verificación no es válido, ya se usó o venció. Pide uno nuevo.");
    }

    public InvalidVerificationTokenException(String message) {
        super(message);
    }
}
