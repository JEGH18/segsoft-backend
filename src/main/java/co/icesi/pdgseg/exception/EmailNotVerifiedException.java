package co.icesi.pdgseg.exception;

/** The password was right but the account's email is still unverified. */
public class EmailNotVerifiedException extends RuntimeException {

    private final String email;

    public EmailNotVerifiedException(String email) {
        super("Debes verificar tu correo antes de iniciar sesión. Revisa tu bandeja de entrada o pide un nuevo enlace.");
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
