package co.icesi.pdgseg.exception;

public class InvalidPasswordResetTokenException extends RuntimeException {
    public InvalidPasswordResetTokenException() {
        super("El enlace para cambiar la contraseña no es válido, ya se usó o venció. Pide uno nuevo.");
    }
}
