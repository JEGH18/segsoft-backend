package co.icesi.pdgseg.service;

import jakarta.mail.Message;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;

import java.time.Duration;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthMailerTest {

    private static final VerificationEmailRequested EVENT =
            new VerificationEmailRequested("juan", "juan@example.com", "abc_DEF-123");

    @SuppressWarnings("unchecked")
    private static AuthMailer mailer(JavaMailSender sender, String host, boolean logLinks) {
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(sender);
        return new AuthMailer(provider, host, "no-reply@segsoft.website", "SegSoft",
                "https://www.segsoft.website/", Duration.ofHours(24), logLinks);
    }

    private static JavaMailSender realMessages() {
        JavaMailSender sender = mock(JavaMailSender.class);
        when(sender.createMimeMessage()).thenAnswer(i -> new MimeMessage(Session.getInstance(new Properties())));
        return sender;
    }

    /** The decoded text of every part, so the transfer encoding does not split the link. */
    private static String text(Part part) throws Exception {
        Object content = part.getContent();
        if (content instanceof Multipart multipart) {
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < multipart.getCount(); i++) {
                text.append(text(multipart.getBodyPart(i)));
            }
            return text.toString();
        }
        return String.valueOf(content);
    }

    @Test
    void theLinkPointsToThePublicFrontendUrl() {
        assertThat(mailer(null, "", false).verificationLink("abc_DEF-123"))
                .isEqualTo("https://www.segsoft.website/verify-email?token=abc_DEF-123");
    }

    @Test
    void sendsTheLinkToTheRegisteredEmail() throws Exception {
        JavaMailSender sender = realMessages();

        mailer(sender, "smtp-relay.brevo.com", false).send(EVENT);

        ArgumentCaptor<MimeMessage> sent = ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(sent.capture());
        MimeMessage message = sent.getValue();
        assertThat(message.getRecipients(Message.RecipientType.TO)[0].toString()).isEqualTo("juan@example.com");
        assertThat(message.getFrom()[0].toString()).contains("no-reply@segsoft.website");
        assertThat(message.getSubject()).isEqualTo("Verifica tu correo en SegSoft");
        assertThat(text(message))
                .contains("https://www.segsoft.website/verify-email?token=abc_DEF-123");
    }

    @Test
    void sendsTheUnlockLinkWhenAnAccountIsLocked() throws Exception {
        JavaMailSender sender = realMessages();

        mailer(sender, "smtp-relay.brevo.com", false)
                .send(new AccountUnlockRequested("juan", "juan@example.com", "xyz_789", 5, 30));

        ArgumentCaptor<MimeMessage> sent = ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(sent.capture());
        MimeMessage message = sent.getValue();
        assertThat(message.getRecipients(Message.RecipientType.TO)[0].toString()).isEqualTo("juan@example.com");
        assertThat(message.getSubject()).isEqualTo("Tu cuenta de SegSoft se bloqueó");
        assertThat(text(message))
                .contains("https://www.segsoft.website/unlock-account?token=xyz_789")
                .contains("5 intentos fallidos")
                .contains("30 minutos");
    }

    @Test
    void isUnavailableWithoutAnSmtpHost_evenIfSpringCreatedTheSender() {
        JavaMailSender sender = realMessages();
        AuthMailer mailer = mailer(sender, "", false);

        assertThat(mailer.isAvailable()).isFalse();
        mailer.send(EVENT);
        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test
    void localDevelopmentCanLogTheLinkInstead() {
        assertThat(mailer(null, "", true).isAvailable()).isTrue();
        assertThat(mailer(realMessages(), "smtp-relay.brevo.com", false).isAvailable()).isTrue();
    }

    @Test
    void anSmtpFailureDoesNotPropagate() {
        JavaMailSender sender = realMessages();
        doThrow(new MailSendException("caído")).when(sender).send(any(MimeMessage.class));

        assertThatCode(() -> mailer(sender, "smtp-relay.brevo.com", false).send(EVENT)).doesNotThrowAnyException();
    }
}
