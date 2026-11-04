package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.entity.EmailVerificationToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.EmailDeliveryUnavailableException;
import co.icesi.pdgseg.exception.InvalidVerificationTokenException;
import co.icesi.pdgseg.exception.TooManyRequestsException;
import co.icesi.pdgseg.repository.EmailVerificationTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
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

class EmailVerificationServiceTest {

    private EmailVerificationTokenRepository tokenRepository;
    private UserRepository userRepository;
    private AuthService authService;
    private AuditService auditService;
    private RegistrationRateLimiter rateLimiter;
    private AuthMailer mailer;
    private ApplicationEventPublisher eventPublisher;
    private EmailVerificationService service;

    @BeforeEach
    void setUp() {
        tokenRepository = mock(EmailVerificationTokenRepository.class);
        userRepository = mock(UserRepository.class);
        authService = mock(AuthService.class);
        auditService = mock(AuditService.class);
        rateLimiter = mock(RegistrationRateLimiter.class);
        mailer = mock(AuthMailer.class);
        eventPublisher = mock(ApplicationEventPublisher.class);
        when(mailer.isAvailable()).thenReturn(true);
        when(authService.startSession(any(User.class)))
                .thenReturn(new AuthResponse("access", "refresh", List.of("DEVELOPER")));
        service = new EmailVerificationService(tokenRepository, userRepository, authService, auditService,
                rateLimiter, mailer, eventPublisher, Duration.ofHours(24), Duration.ofDays(7));
    }

    private static User pendingUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("juan");
        user.setEmail("juan@example.com");
        user.setEnabled(true);
        return user;
    }

    /** Issues a link for {@code user} and returns the raw token that would be emailed. */
    private String issuedToken(User user) {
        service.issue(user);
        ArgumentCaptor<VerificationEmailRequested> event = ArgumentCaptor.forClass(VerificationEmailRequested.class);
        verify(eventPublisher).publishEvent(event.capture());
        return event.getValue().token();
    }

    @Test
    void issue_storesOnlyTheHashOfARandomToken_andPublishesTheEmail() {
        User user = pendingUser();

        String token = issuedToken(user);

        ArgumentCaptor<EmailVerificationToken> stored = ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(tokenRepository).save(stored.capture());
        assertThat(token).hasSize(43).matches("[A-Za-z0-9_-]+");
        assertThat(stored.getValue().getTokenHash()).isEqualTo(ReportChecksum.sha256Hex(token)).isNotEqualTo(token);
        assertThat(stored.getValue().getUser()).isSameAs(user);
        assertThat(stored.getValue().getExpiresAt())
                .isBetween(OffsetDateTime.now().plusHours(23), OffsetDateTime.now().plusHours(25));
        verify(tokenRepository).invalidatePending(eq(user.getId()), any(OffsetDateTime.class));
    }

    @Test
    void verify_marksTheEmailAsVerified_consumesTheToken_andStartsTheSession() {
        User user = pendingUser();
        EmailVerificationToken stored = new EmailVerificationToken(user, ReportChecksum.sha256Hex("tok"),
                OffsetDateTime.now().plusHours(1));
        when(tokenRepository.findByTokenHash(ReportChecksum.sha256Hex("tok"))).thenReturn(Optional.of(stored));

        AuthResponse auth = service.verify(" tok ", "ip");

        assertThat(auth.accessToken()).isEqualTo("access");
        assertThat(user.getEmailVerifiedAt()).isNotNull();
        assertThat(user.isEmailPendingVerification()).isFalse();
        assertThat(stored.getUsedAt()).isNotNull();
        verify(auditService).record("EMAIL_VERIFIED", "juan", "ip", Map.of());
    }

    @Test
    void verify_doesNotStartASessionForALockedAccount_norUseUpTheLink() {
        User user = pendingUser();
        user.setLockedUntil(OffsetDateTime.now().plusMinutes(20));
        EmailVerificationToken stored = new EmailVerificationToken(user, ReportChecksum.sha256Hex("tok"),
                OffsetDateTime.now().plusHours(1));
        when(tokenRepository.findByTokenHash(ReportChecksum.sha256Hex("tok"))).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.verify("tok", "ip"))
                .isInstanceOf(AccountLockedException.class)
                .hasMessageContaining("bloqueada");

        assertThat(stored.getUsedAt()).isNull();
        assertThat(user.getEmailVerifiedAt()).isNull();
        verifyNoInteractions(authService);
    }

    @Test
    void verify_rejectsAnUnknownToken() {
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verify("desconocido", "ip"))
                .isInstanceOf(InvalidVerificationTokenException.class);
        verifyNoInteractions(authService);
    }

    @Test
    void verify_rejectsAnExpiredToken() {
        User user = pendingUser();
        EmailVerificationToken stored = new EmailVerificationToken(user, "h", OffsetDateTime.now().minusMinutes(1));
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.verify("tok", "ip"))
                .isInstanceOf(InvalidVerificationTokenException.class)
                .hasMessageContaining("venció");
        assertThat(user.getEmailVerifiedAt()).isNull();
        verifyNoInteractions(authService);
    }

    @Test
    void verify_rejectsAUsedToken_sayingSoWhenTheEmailIsAlreadyVerified() {
        User user = pendingUser();
        user.setEmailVerifiedAt(OffsetDateTime.now());
        EmailVerificationToken stored = new EmailVerificationToken(user, "h", OffsetDateTime.now().plusHours(1));
        stored.setUsedAt(OffsetDateTime.now());
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.verify("tok", "ip"))
                .isInstanceOf(InvalidVerificationTokenException.class)
                .hasMessageContaining("ya está verificado");
        verifyNoInteractions(authService);
    }

    @Test
    void verify_rejectsTheTokenOfADisabledAccount() {
        User user = pendingUser();
        user.setEnabled(false);
        EmailVerificationToken stored = new EmailVerificationToken(user, "h", OffsetDateTime.now().plusHours(1));
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.verify("tok", "ip"))
                .isInstanceOf(InvalidVerificationTokenException.class);
        verifyNoInteractions(authService);
    }

    @Test
    void resend_issuesANewLinkForAPendingAccount() {
        User user = pendingUser();
        when(userRepository.findByEmailIgnoreCase("juan@example.com")).thenReturn(Optional.of(user));

        service.resend(" JUAN@example.com ", "ip");

        verify(tokenRepository).save(any(EmailVerificationToken.class));
        verify(eventPublisher).publishEvent(any(VerificationEmailRequested.class));
        verify(auditService).record("VERIFICATION_EMAIL_RESENT", "juan", "ip", Map.of());
    }

    @Test
    void resend_sendsNothingForAnUnknownOrAlreadyVerifiedEmail() {
        User verified = pendingUser();
        verified.setEmailVerifiedAt(OffsetDateTime.now());
        when(userRepository.findByEmailIgnoreCase("juan@example.com")).thenReturn(Optional.of(verified));

        service.resend("juan@example.com", "ip");
        service.resend("nadie@example.com", "ip");

        verify(tokenRepository, never()).save(any());
        verifyNoInteractions(eventPublisher);
    }

    @Test
    void resend_waitsForTheCooldownBeforeSendingAgain() {
        User user = pendingUser();
        when(userRepository.findByEmailIgnoreCase("juan@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.existsByUserIdAndCreatedAtAfter(eq(user.getId()), any())).thenReturn(true);

        service.resend("juan@example.com", "ip");

        verify(tokenRepository, never()).save(any());
        verifyNoInteractions(eventPublisher);
    }

    @Test
    void resend_countsAgainstTheIpLimit_andFailsWithoutEmailDelivery() {
        doThrow(new TooManyRequestsException("limite")).when(rateLimiter).checkAttempt("ip");
        assertThatThrownBy(() -> service.resend("juan@example.com", "ip"))
                .isInstanceOf(TooManyRequestsException.class);

        when(mailer.isAvailable()).thenReturn(false);
        assertThatThrownBy(() -> service.resend("juan@example.com", "otra-ip"))
                .isInstanceOf(EmailDeliveryUnavailableException.class);
        verifyNoInteractions(userRepository);
    }
}
