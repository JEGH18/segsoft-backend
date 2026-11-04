package co.icesi.pdgseg.exception;

public class InvalidUnlockTokenException extends RuntimeException {
    public InvalidUnlockTokenException() {
        super("El enlace de desbloqueo no es válido, ya se usó o venció. Si la cuenta sigue bloqueada, "
                + "espera a que termine el bloqueo e inicia sesión de nuevo.");
    }
}
