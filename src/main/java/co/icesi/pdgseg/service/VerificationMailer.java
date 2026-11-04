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
 * Sends the verification link over SMTP (Brevo in production, configured with MAIL_*).
 *
 * <p>The link is built from {@code app.public-url}, never from the request's Host header, so a
 * forged header cannot make the email point to another site.
 */
@Component
public class VerificationMailer {

    private static final Logger log = LoggerFactory.getLogger(VerificationMailer.class);

    private final ObjectProvider<JavaMailSender> mailSender;
    private final boolean smtpConfigured;
    private final String from;
    private final String fromName;
    private final String publicUrl;
    private final Duration tokenTtl;
    private final boolean logLinks;

    public VerificationMailer(ObjectProvider<JavaMailSender> mailSender,
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
     * Whether a verification email can reach the user: an SMTP server is configured (spring.mail.host),
     * or, only in local development, the link is written to the log.
     */
    public boolean isAvailable() {
        return sender() != null || logLinks;
    }

    @Async("mailExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onVerificationRequested(VerificationEmailRequested event) {
        send(event);
    }

    void send(VerificationEmailRequested event) {
        String link = verificationLink(event.token());
        JavaMailSender sender = sender();
        if (sender == null) {
            if (logLinks) {
                log.warn("SMTP sin configurar; enlace de verificación de usuario={}: {}", event.username(), link);
            } else {
                log.error("SMTP sin configurar; no se envió el correo de verificación de usuario={}", event.username());
            }
            return;
        }
        try {
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(from, fromName);
            helper.setTo(event.email());
            helper.setSubject("Verifica tu correo en SegSoft");
            helper.setText(plainText(event.username(), link), html(event.username(), link));
            sender.send(message);
            log.info("Correo de verificación enviado a usuario={}", event.username());
        } catch (Exception e) {
            // The user can ask for a new link from the login or the registration screen.
            log.error("No se pudo enviar el correo de verificación de usuario={}", event.username(), e);
        }
    }

    /** Spring Boot creates the sender even when MAIL_HOST is empty, so the host is checked too. */
    private JavaMailSender sender() {
        return smtpConfigured ? mailSender.getIfAvailable() : null;
    }

    String verificationLink(String token) {
        return UriComponentsBuilder.fromHttpUrl(publicUrl)
                .path("/verify-email")
                .queryParam("token", token)
                .build()
                .toUriString();
    }

    private String plainText(String username, String link) {
        return """
                Hola %s:

                Para activar tu cuenta de SegSoft, abre este enlace:

                %s

                El enlace vence en %d horas y solo se puede usar una vez.
                Si no creaste esta cuenta, ignora este correo.
                """.formatted(username, link, tokenTtl.toHours());
    }

    private String html(String username, String link) {
        String safeName = HtmlUtils.htmlEscape(username);
        String safeLink = HtmlUtils.htmlEscape(link);
        return """
                <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;color:#171717">
                  <h2 style="margin:0 0 16px">Verifica tu correo</h2>
                  <p>Hola <strong>%s</strong>:</p>
                  <p>Para activar tu cuenta de SegSoft, confirma que este correo es tuyo.</p>
                  <p style="margin:24px 0">
                    <a href="%s" style="background:#171717;color:#ffffff;padding:12px 20px;border-radius:8px;text-decoration:none;display:inline-block">Verificar correo</a>
                  </p>
                  <p style="font-size:13px;color:#525252">Si el botón no funciona, copia este enlace en el navegador:<br>
                    <a href="%s" style="color:#525252;word-break:break-all">%s</a></p>
                  <p style="font-size:13px;color:#525252">El enlace vence en %d horas y solo se puede usar una vez.
                    Si no creaste esta cuenta, ignora este correo.</p>
                </div>
                """.formatted(safeName, safeLink, safeLink, safeLink, tokenTtl.toHours());
    }
}
