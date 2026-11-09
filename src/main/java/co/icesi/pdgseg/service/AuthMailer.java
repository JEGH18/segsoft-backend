package co.icesi.pdgseg.service;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;

/**
 * Sends the account emails over SMTP (Brevo in production, configured with MAIL_*): the link that
 * verifies the email of a new account and the link that unlocks an account locked by failed logins.
 *
 * <p>Links are built from {@code app.public-url}, never from the request's Host header, so a
 * forged header cannot make an email point to another site.
 */
@Component
public class AuthMailer {

    private static final Logger log = LoggerFactory.getLogger(AuthMailer.class);

    private final ObjectProvider<JavaMailSender> mailSender;
    private final boolean smtpConfigured;
    private final String from;
    private final String fromName;
    private final String publicUrl;
    private final Duration tokenTtl;
    private final boolean logLinks;

    public AuthMailer(ObjectProvider<JavaMailSender> mailSender,
                      @Value("${spring.mail.host:}") String mailHost,
                      @Value("${auth.email-verification.from:no-reply@segsoft.website}") String from,
                      @Value("${auth.email-verification.from-name:SegSoft}") String fromName,
                      @Value("${app.public-url:http://localhost:5173}") String publicUrl,
                      @Value("${auth.email-verification.token-ttl:PT24H}") Duration tokenTtl,
                      @Value("${auth.email-verification.log-links:false}") boolean logLinks) {
        this.mailSender     = mailSender;
        this.smtpConfigured = StringUtils.hasText(mailHost);
        this.from           = from;
        this.fromName       = fromName;
        this.publicUrl      = publicUrl.trim().replaceAll("/+$", "");
        this.tokenTtl       = tokenTtl;
        this.logLinks       = logLinks;
    }

    /**
     * Whether an email can reach the user: an SMTP server is configured (spring.mail.host), or,
     * only in local development, the link is written to the log.
     */
    public boolean isAvailable() {
        return sender() != null || logLinks;
    }

    @Async("mailExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onVerificationRequested(VerificationEmailRequested event) {
        send(event);
    }

    @Async("mailExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onUnlockRequested(AccountUnlockRequested event) {
        send(event);
    }

    @Async("mailExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPasswordResetRequested(PasswordResetRequested event) {
        send(event);
    }

    @Async("mailExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPasswordChanged(PasswordChanged event) {
        send(event);
    }

    void send(VerificationEmailRequested event) {
        String link = verificationLink(event.token());
        deliver("verificación", event.username(), event.email(), "Verifica tu correo en SegSoft", link,
                verificationText(event.username(), link), verificationHtml(event.username(), link));
    }

    void send(AccountUnlockRequested event) {
        String link = unlockLink(event.token());
        deliver("desbloqueo", event.username(), event.email(), "Tu cuenta de SegSoft se bloqueó", link,
                unlockText(event, link), unlockHtml(event, link));
    }

    void send(PasswordResetRequested event) {
        String link = passwordResetLink(event.token());
        deliver("cambio de contraseña", event.username(), event.email(), "Cambia tu contraseña de SegSoft", link,
                passwordResetText(event, link), passwordResetHtml(event, link));
    }

    void send(PasswordChanged event) {
        String link = UriComponentsBuilder.fromHttpUrl(publicUrl).path("/forgot-password").build().toUriString();
        deliver("aviso de contraseña cambiada", event.username(), event.email(), "Tu contraseña de SegSoft cambió",
                link, passwordChangedText(event.username(), link), passwordChangedHtml(event.username(), link));
    }

    String passwordResetLink(String token) {
        return link("/reset-password", token);
    }

    String verificationLink(String token) {
        return link("/verify-email", token);
    }

    String unlockLink(String token) {
        return link("/unlock-account", token);
    }

    private void deliver(String kind, String username, String to, String subject, String link,
                         String text, String html) {
        JavaMailSender sender = sender();
        if (sender == null) {
            if (logLinks) {
                log.warn("SMTP sin configurar; enlace de {} de usuario={}: {}", kind, username, link);
            } else {
                log.error("SMTP sin configurar; no se envió el correo de {} de usuario={}", kind, username);
            }
            return;
        }
        try {
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(from, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, html);
            sender.send(message);
            log.info("Correo de {} enviado a usuario={}", kind, username);
        } catch (Exception e) {
            // Verification: a new link can be asked for. Unlock: the lock still expires on its own.
            log.error("No se pudo enviar el correo de {} de usuario={}", kind, username, e);
        }
    }

    /** Spring Boot creates the sender even when MAIL_HOST is empty, so the host is checked too. */
    private JavaMailSender sender() {
        return smtpConfigured ? mailSender.getIfAvailable() : null;
    }

    private String link(String path, String token) {
        return UriComponentsBuilder.fromHttpUrl(publicUrl)
                .path(path)
                .queryParam("token", token)
                .build()
                .toUriString();
    }

    private String verificationText(String username, String link) {
        return """
                Hola %s:

                Para activar tu cuenta de SegSoft, abre este enlace:

                %s

                El enlace vence en %d horas y solo se puede usar una vez.
                Si no creaste esta cuenta, ignora este correo.
                """.formatted(username, link, tokenTtl.toHours());
    }

    private String verificationHtml(String username, String link) {
        return page("Verifica tu correo", username,
                "<p>Para activar tu cuenta de SegSoft, confirma que este correo es tuyo.</p>",
                "Verificar correo", link,
                "El enlace vence en %d horas y solo se puede usar una vez. Si no creaste esta cuenta, ignora este correo."
                        .formatted(tokenTtl.toHours()));
    }

    private String unlockText(AccountUnlockRequested event, String link) {
        return """
                Hola %s:

                Hubo %d intentos fallidos de iniciar sesión en tu cuenta de SegSoft, así que la
                bloqueamos durante %d minutos.

                Si fuiste tú, puedes desbloquearla ahora con este enlace:

                %s

                El enlace solo se puede usar una vez y vence cuando termina el bloqueo.
                Si no fuiste tú, alguien está intentando adivinar tu contraseña: no abras el enlace
                y avísale al administrador de SegSoft.
                """.formatted(event.username(), event.failedAttempts(), event.lockMinutes(), link);
    }

    private String unlockHtml(AccountUnlockRequested event, String link) {
        return page("Tu cuenta se bloqueó", event.username(),
                ("<p>Hubo %d intentos fallidos de iniciar sesión en tu cuenta de SegSoft, así que la "
                        + "bloqueamos durante %d minutos.</p><p>Si fuiste tú, puedes desbloquearla ahora.</p>")
                        .formatted(event.failedAttempts(), event.lockMinutes()),
                "Desbloquear cuenta", link,
                "El enlace solo se puede usar una vez y vence cuando termina el bloqueo. Si no fuiste tú, "
                        + "alguien está intentando adivinar tu contraseña: no abras el enlace y avísale al "
                        + "administrador de SegSoft.");
    }

    private String passwordResetText(PasswordResetRequested event, String link) {
        return """
                Hola %s:

                Alguien pidió cambiar la contraseña de tu cuenta de SegSoft. Si fuiste tú, elige una
                nueva con este enlace:

                %s

                El enlace vence en %d minutos y solo se puede usar una vez. Al cambiarla se cierran
                todas las sesiones abiertas.
                Si no lo pediste, ignora este correo: tu contraseña no cambia.
                """.formatted(event.username(), link, event.validMinutes());
    }

    private String passwordResetHtml(PasswordResetRequested event, String link) {
        return page("Cambia tu contraseña", event.username(),
                "<p>Alguien pidió cambiar la contraseña de tu cuenta de SegSoft. Si fuiste tú, elige una nueva.</p>",
                "Cambiar contraseña", link,
                ("El enlace vence en %d minutos y solo se puede usar una vez. Al cambiarla se cierran todas las "
                        + "sesiones abiertas. Si no lo pediste, ignora este correo: tu contraseña no cambia.")
                        .formatted(event.validMinutes()));
    }

    private String passwordChangedText(String username, String link) {
        return """
                Hola %s:

                La contraseña de tu cuenta de SegSoft acaba de cambiar y se cerraron todas las
                sesiones abiertas.

                Si fuiste tú, no tienes que hacer nada.
                Si no fuiste tú, recupera tu cuenta ahora con este enlace y avísale al administrador
                de SegSoft:

                %s
                """.formatted(username, link);
    }

    private String passwordChangedHtml(String username, String link) {
        return page("Tu contraseña cambió", username,
                "<p>La contraseña de tu cuenta de SegSoft acaba de cambiar y se cerraron todas las sesiones "
                        + "abiertas.</p><p>Si fuiste tú, no tienes que hacer nada.</p>",
                "No fui yo: recuperar mi cuenta", link,
                "Si no fuiste tú, recupera tu cuenta con el botón y avísale al administrador de SegSoft.");
    }

    /** The HTML layout shared by every email; {@code body} and {@code footer} are trusted text. */
    private static String page(String title, String username, String body, String button, String link,
                               String footer) {
        String safeName = HtmlUtils.htmlEscape(username);
        String safeLink = HtmlUtils.htmlEscape(link);
        return """
                <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;color:#171717">
                  <h2 style="margin:0 0 16px">%s</h2>
                  <p>Hola <strong>%s</strong>:</p>
                  %s
                  <p style="margin:24px 0">
                    <a href="%s" style="background:#171717;color:#ffffff;padding:12px 20px;border-radius:8px;text-decoration:none;display:inline-block">%s</a>
                  </p>
                  <p style="font-size:13px;color:#525252">Si el botón no funciona, copia este enlace en el navegador:<br>
                    <a href="%s" style="color:#525252;word-break:break-all">%s</a></p>
                  <p style="font-size:13px;color:#525252">%s</p>
                </div>
                """.formatted(title, safeName, body, safeLink, button, safeLink, safeLink, footer);
    }
}
