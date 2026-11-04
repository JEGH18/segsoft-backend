package co.icesi.pdgseg.exception;

/** The deployment has no SMTP server configured, so no verification email could be sent. */
public class EmailDeliveryUnavailableException extends RuntimeException {
    public EmailDeliveryUnavailableException() {
        super("El registro no está disponible por ahora: el envío de correos no está configurado. "
                + "Avisa al administrador de SegSoft.");
    }
}
