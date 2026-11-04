package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.AccountUnlockToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.InvalidUnlockTokenException;
import co.icesi.pdgseg.repository.AccountUnlockTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AccountUnlockServiceTest {

    private AccountUnlockTokenRepository tokenRepository;
    private UserRepository userRepository;
    private AuditService auditService;
    private AuthMailer mailer;
    private ApplicationEventPublisher eventPublisher;
    private AccountUnlockService service;

    @BeforeEach
    void setUp() {
        tokenRepository = mock(AccountUnlockTokenRepository.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);
        mailer = mock(AuthMailer.class);
        eventPublisher = mock(ApplicationEventPublisher.class);
        when(mailer.isAvailable()).thenReturn(true);
        service = new AccountUnlockService(tokenRepository, userRepository, auditService, mailer, eventPublisher);
    }

    private static User lockedUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("juan");
        user.setEmail("juan@example.com");
        user.setEmailVerifiedAt(OffsetDateTime.now().minusDays(1));
        user.setEnabled(true);
        user.setLockedUntil(OffsetDateTime.now().plusMinutes(30));
        return user;
    }

    @Test
    void issue_storesTheHashOfALinkThatExpiresWithTheLock_andPublishesTheEmail() {
        User user = lockedUser();

        assertThat(service.issue(user, 5)).isTrue();

        ArgumentCaptor<AccountUnlockRequested> event = ArgumentCaptor.forClass(AccountUnlockRequested.class);
        verify(eventPublisher).publishEvent(event.capture());
        ArgumentCaptor<AccountUnlockToken> stored = ArgumentCaptor.forClass(AccountUnlockToken.class);
        verify(tokenRepository).save(stored.capture());
        String token = event.getValue().token();
        assertThat(stored.getValue().getTokenHash()).isEqualTo(OneTimeTokens.hash(token)).isNotEqualTo(token);
        assertThat(stored.getValue().getExpiresAt()).isEqualTo(user.getLockedUntil());
        assertThat(event.getValue().email()).isEqualTo("juan@example.com");
        assertThat(event.getValue().failedAttempts()).isEqualTo(5);
        assertThat(event.getValue().lockMinutes()).isBetween(29L, 30L);
        verify(tokenRepository).invalidatePending(eq(user.getId()), any(OffsetDateTime.class));
    }

    @Test
    void issue_sendsNothingWithoutAVerifiedEmail_orWithoutSmtp() {
        User withoutEmail = lockedUser();
        withoutEmail.setEmail(null);
        User unverified = lockedUser();
        unverified.setEmailVerifiedAt(null);

        assertThat(service.issue(withoutEmail, 5)).isFalse();
        assertThat(service.issue(unverified, 5)).isFalse();
        when(mailer.isAvailable()).thenReturn(false);
        assertThat(service.issue(lockedUser(), 5)).isFalse();

        verifyNoInteractions(tokenRepository, eventPublisher);
    }

    @Test
    void unlock_liftsTheLock_consumesTheLink_andAudits() {
        User user = lockedUser();
        user.setFailedAttempts(3);
        user.setLastFailedAt(OffsetDateTime.now());
        AccountUnlockToken stored = new AccountUnlockToken(user, OneTimeTokens.hash("tok"), user.getLockedUntil());
        when(tokenRepository.findByTokenHash(OneTimeTokens.hash("tok"))).thenReturn(Optional.of(stored));

        service.unlock(" tok ", "ip");

        assertThat(user.getLockedUntil()).isNull();
        assertThat(user.getFailedAttempts()).isZero();
        assertThat(user.getLastFailedAt()).isNull();
        assertThat(stored.getUsedAt()).isNotNull();
        verify(userRepository).save(user);
        verify(auditService).record("ACCOUNT_UNLOCKED", "juan", "ip", Map.of("via", "email"));
    }

    @Test
    void unlock_rejectsAnUnknownUsedOrExpiredLink() {
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.unlock("desconocido", "ip")).isInstanceOf(InvalidUnlockTokenException.class);

        User user = lockedUser();
        AccountUnlockToken used = new AccountUnlockToken(user, "h", user.getLockedUntil());
        used.setUsedAt(OffsetDateTime.now());
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(used));
        assertThatThrownBy(() -> service.unlock("usado", "ip")).isInstanceOf(InvalidUnlockTokenException.class);

        AccountUnlockToken expired = new AccountUnlockToken(user, "h", OffsetDateTime.now().minusMinutes(1));
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(expired));
        assertThatThrownBy(() -> service.unlock("vencido", "ip")).isInstanceOf(InvalidUnlockTokenException.class);

        assertThat(user.getLockedUntil()).isNotNull();
        verifyNoInteractions(userRepository, auditService);
    }
}
