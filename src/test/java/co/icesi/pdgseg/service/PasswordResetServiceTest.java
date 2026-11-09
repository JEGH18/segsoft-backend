package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.PasswordResetToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.EmailDeliveryUnavailableException;
import co.icesi.pdgseg.exception.InvalidPasswordResetTokenException;
import co.icesi.pdgseg.exception.TooManyRequestsException;
import co.icesi.pdgseg.repository.PasswordResetTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PasswordResetServiceTest {

    private static final String NEW_PASSWORD = "Nueva-Clave-2026!";

    private PasswordResetTokenRepository tokenRepository;
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private AuditService auditService;
    private RegistrationRateLimiter rateLimiter;
    private AuthMailer mailer;
    private ApplicationEventPublisher eventPublisher;
    private PasswordResetService service;

    @BeforeEach
    void setUp() {
        tokenRepository = mock(PasswordResetTokenRepository.class);
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        auditService = mock(AuditService.class);
        rateLimiter = mock(RegistrationRateLimiter.class);
        mailer = mock(AuthMailer.class);
        eventPublisher = mock(ApplicationEventPublisher.class);
        when(mailer.isAvailable()).thenReturn(true);
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn("hash-nuevo");
        service = new PasswordResetService(tokenRepository, userRepository, passwordEncoder, auditService,
                rateLimiter, mailer, eventPublisher, Duration.ofMinutes(30));
    }

    private static User verifiedUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("juan");
        user.setEmail("juan@example.com");
        user.setEmailVerifiedAt(OffsetDateTime.now().minusDays(1));
        user.setPasswordHash("hash-viejo");
        user.setEnabled(true);
        return user;
    }

    private static PasswordResetToken usableToken(User user) {
        return new PasswordResetToken(user, ReportChecksum.sha256Hex("tok"), OffsetDateTime.now().plusMinutes(10));
    }

    @Test
    void request_emailsASingleUseLink_storingOnlyItsHash() {
        User user = verifiedUser();
        when(userRepository.findByEmailIgnoreCase("juan@example.com")).thenReturn(Optional.of(user));

        service.request(" Juan@Example.com ", "ip");

        ArgumentCaptor<PasswordResetRequested> event = ArgumentCaptor.forClass(PasswordResetRequested.class);
        verify(eventPublisher).publishEvent(event.capture());
        ArgumentCaptor<PasswordResetToken> stored = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(stored.capture());
        String token = event.getValue().token();
        assertThat(event.getValue().email()).isEqualTo("juan@example.com");
        assertThat(event.getValue().validMinutes()).isEqualTo(30);
        assertThat(stored.getValue().getTokenHash()).isEqualTo(ReportChecksum.sha256Hex(token)).isNotEqualTo(token);
        assertThat(stored.getValue().getExpiresAt())
                .isBetween(OffsetDateTime.now().plusMinutes(29), OffsetDateTime.now().plusMinutes(31));
        verify(tokenRepository).invalidatePending(eq(user.getId()), any(OffsetDateTime.class));
        verify(auditService).record("PASSWORD_RESET_REQUESTED", "juan", "ip", Map.of());
    }

    @Test
    void request_sendsNothing_forAnUnknownEmail_anUnverifiedOne_orADisabledAccount() {
        User unverified = verifiedUser();
        unverified.setEmailVerifiedAt(null);
        User disabled = verifiedUser();
        disabled.setEmail("off@example.com");
        disabled.setEnabled(false);
        when(userRepository.findByEmailIgnoreCase("juan@example.com")).thenReturn(Optional.of(unverified));
        when(userRepository.findByEmailIgnoreCase("off@example.com")).thenReturn(Optional.of(disabled));

        service.request("nadie@example.com", "ip");
        service.request("juan@example.com", "ip");
        service.request("off@example.com", "ip");

        verify(tokenRepository, never()).save(any());
        verifyNoInteractions(eventPublisher);
    }

    @Test
    void request_waitsForTheCooldownBeforeSendingAgain() {
        User user = verifiedUser();
        when(userRepository.findByEmailIgnoreCase("juan@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.existsByUserIdAndCreatedAtAfter(eq(user.getId()), any())).thenReturn(true);

        service.request("juan@example.com", "ip");

        verify(tokenRepository, never()).save(any());
        verifyNoInteractions(eventPublisher);
    }

    @Test
    void request_countsAgainstTheIpLimit_andFailsWithoutEmailDelivery() {
        doThrow(new TooManyRequestsException("limite")).when(rateLimiter).checkAttempt("ip");
        assertThatThrownBy(() -> service.request("juan@example.com", "ip"))
                .isInstanceOf(TooManyRequestsException.class);

        when(mailer.isAvailable()).thenReturn(false);
        assertThatThrownBy(() -> service.request("juan@example.com", "otra-ip"))
                .isInstanceOf(EmailDeliveryUnavailableException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void reset_setsTheNewPassword_endsEverySession_liftsTheLock_andConsumesTheLink() {
        User user = verifiedUser();
        user.setTokenVersion(2);
        user.setFailedAttempts(3);
        user.setLockedUntil(OffsetDateTime.now().plusMinutes(20));
        PasswordResetToken stored = usableToken(user);
        when(tokenRepository.findByTokenHash(ReportChecksum.sha256Hex("tok"))).thenReturn(Optional.of(stored));

        service.reset(" tok ", NEW_PASSWORD, "ip");

        assertThat(user.getPasswordHash()).isEqualTo("hash-nuevo");
        assertThat(user.getTokenVersion()).isEqualTo(3);
        assertThat(user.getLockedUntil()).isNull();
        assertThat(user.getFailedAttempts()).isZero();
        assertThat(stored.getUsedAt()).isNotNull();
        verify(tokenRepository).invalidatePending(eq(user.getId()), any(OffsetDateTime.class));
        verify(userRepository).save(user);
        verify(auditService).record("PASSWORD_RESET", "juan", "ip", Map.of("via", "email"));
        verify(eventPublisher).publishEvent(new PasswordChanged("juan", "juan@example.com"));
    }

    @Test
    void reset_rejectsTheCurrentPassword_withoutUsingUpTheLink() {
        User user = verifiedUser();
        PasswordResetToken stored = usableToken(user);
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));
        when(passwordEncoder.matches(NEW_PASSWORD, "hash-viejo")).thenReturn(true);

        assertThatThrownBy(() -> service.reset("tok", NEW_PASSWORD, "ip"))
                .isInstanceOf(BusinessValidationException.class)
                .hasMessageContaining("distinta de la actual");

        assertThat(stored.getUsedAt()).isNull();
        assertThat(user.getPasswordHash()).isEqualTo("hash-viejo");
        verify(userRepository, never()).save(any());
    }

    @Test
    void reset_rejectsUnknownUsedAndExpiredLinks_andDisabledAccounts() {
        when(tokenRepository.findByTokenHash(ReportChecksum.sha256Hex("desconocido"))).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.reset("desconocido", NEW_PASSWORD, "ip"))
                .isInstanceOf(InvalidPasswordResetTokenException.class);

        User user = verifiedUser();
        PasswordResetToken used = usableToken(user);
        used.setUsedAt(OffsetDateTime.now().minusMinutes(1));
        when(tokenRepository.findByTokenHash(ReportChecksum.sha256Hex("usado"))).thenReturn(Optional.of(used));
        assertThatThrownBy(() -> service.reset("usado", NEW_PASSWORD, "ip"))
                .isInstanceOf(InvalidPasswordResetTokenException.class);

        PasswordResetToken expired = new PasswordResetToken(user, "h", OffsetDateTime.now().minusSeconds(1));
        when(tokenRepository.findByTokenHash(ReportChecksum.sha256Hex("vencido"))).thenReturn(Optional.of(expired));
        assertThatThrownBy(() -> service.reset("vencido", NEW_PASSWORD, "ip"))
                .isInstanceOf(InvalidPasswordResetTokenException.class);

        User disabled = verifiedUser();
        disabled.setEnabled(false);
        when(tokenRepository.findByTokenHash(ReportChecksum.sha256Hex("apagada")))
                .thenReturn(Optional.of(usableToken(disabled)));
        assertThatThrownBy(() -> service.reset("apagada", NEW_PASSWORD, "ip"))
                .isInstanceOf(InvalidPasswordResetTokenException.class);

        verify(userRepository, never()).save(any());
        verifyNoInteractions(eventPublisher);
    }
}
