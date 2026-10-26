package co.icesi.pdgseg.exception;

public class RegistrationDisabledException extends RuntimeException {
    public RegistrationDisabledException() {
        super("El registro de nuevas cuentas está deshabilitado. Pide una cuenta al administrador.");
    }
}
