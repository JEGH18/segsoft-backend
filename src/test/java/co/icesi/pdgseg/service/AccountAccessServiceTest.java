package co.icesi.pdgseg.service;

import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.entity.ApiToken;
import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.repository.ApiTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import co.icesi.pdgseg.security.ApiTokens;
import org.springframework.test.util.ReflectionTestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountAccessServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-09T12:00:00Z");

    private UserRepository userRepository;
    private ApiTokenRepository apiTokenRepository;
    private AccountAccessService service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        apiTokenRepository = mock(ApiTokenRepository.class);
        service = new AccountAccessService(userRepository, apiTokenRepository, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private void accountIs(Boolean enabled, OffsetDateTime lockedUntil, boolean verifiedEmail) {
        UserRepository.AccessState state = mock(UserRepository.AccessState.class);
        when(state.getEnabled()).thenReturn(enabled);
        when(state.getTokenVersion()).thenReturn(2);
        when(state.getLockedUntil()).thenReturn(lockedUntil);
        when(state.getEmail()).thenReturn(verifiedEmail ? "alice@example.com" : null);
        when(state.getEmailVerifiedAt()).thenReturn(verifiedEmail ? OffsetDateTime.now().minusDays(1) : null);
        when(userRepository.findAccessStateByUsername("alice")).thenReturn(Optional.of(state));
    }

    @Test
    void anEnabledUnlockedAccount_passes() {
        accountIs(true, null, true);
        assertThatCode(() -> service.requireUsable("alice", 2)).doesNotThrowAnyException();
    }

    @Test
    void anAccountWhoseLockIsOver_passes() {
        accountIs(true, OffsetDateTime.now().minusSeconds(1), true);
        assertThatCode(() -> service.requireUsable("alice", 2)).doesNotThrowAnyException();
    }

    @Test
    void aLockedAccount_isRejectedWithTheMinutesLeft_andTheUnlockEmailHint() {
        accountIs(true, OffsetDateTime.now().plusMinutes(12).minusSeconds(30), true);

        assertThatThrownBy(() -> service.requireUsable("alice", 2))
                .isInstanceOfSatisfying(AccountLockedException.class,
                        e -> assertThat(e.getMinutesLeft()).isEqualTo(12))
                .hasMessage("La cuenta está bloqueada por demasiados intentos fallidos. Intenta de nuevo en "
                        + "12 minutos o usa el enlace que te enviamos por correo para desbloquearla.");
    }

    @Test
    void aTokenIssuedBeforeThePasswordChanged_isRejected() {
        accountIs(true, null, true);
        assertThatThrownBy(() -> service.requireUsable("alice", 1))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.PASSWORD_CHANGED);
    }

    @Test
    void aDisabledAccount_isRejected() {
        accountIs(false, null, true);
        assertThatThrownBy(() -> service.requireUsable("alice", 2))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.SESSION_REVOKED);
    }

    @Test
    void aDeletedAccount_isRejected() {
        when(userRepository.findAccessStateByUsername("alice")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.requireUsable("alice", 2))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.SESSION_REVOKED);
    }

    // --- CI/CD API tokens ---

    private static final String PLAINTEXT = "pdgseg_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    private ApiToken apiToken(boolean enabled, OffsetDateTime lockedUntil, OffsetDateTime expiresAt,
                              OffsetDateTime lastUsedAt) {
        Role developer = new Role();
        developer.setName(RoleType.DEVELOPER);
        User owner = new User();
        owner.setUsername("ci-bot");
        owner.setEnabled(enabled);
        owner.setLockedUntil(lockedUntil);
        owner.setRoles(Set.of(developer));

        ApiToken token = new ApiToken();
        ReflectionTestUtils.setField(token, "id", UUID.randomUUID());
        token.setCreatedBy(owner);
        token.setExpiresAt(expiresAt);
        token.setLastUsedAt(lastUsedAt);
        when(apiTokenRepository.findByTokenHash(ApiTokens.hash(PLAINTEXT))).thenReturn(Optional.of(token));
        return token;
    }

    private static OffsetDateTime now() {
        return OffsetDateTime.ofInstant(NOW, ZoneOffset.UTC);
    }

    @Test
    void aValidApiToken_authenticatesAsItsOwnerWithTheOwnersRoles_andRecordsItsUse() {
        ApiToken token = apiToken(true, null, now().plusDays(30), null);

        AccountAccessService.ApiTokenIdentity identity = service.authenticateApiToken(PLAINTEXT);

        assertThat(identity.username()).isEqualTo("ci-bot");
        assertThat(identity.roles()).containsExactly("DEVELOPER");
        verify(apiTokenRepository).markUsed(token.getId(), now());
    }

    @Test
    void anApiTokenUsedLessThanAMinuteAgo_doesNotWriteLastUsedAgain() {
        apiToken(true, null, now().plusDays(30), now().minusSeconds(30));
        service.authenticateApiToken(PLAINTEXT);
        verify(apiTokenRepository, never()).markUsed(any(), any());
    }

    @Test
    void anUnknownApiToken_isRejected() {
        when(apiTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.authenticateApiToken("pdgseg_unknown"))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.API_TOKEN_INVALID);
    }

    @Test
    void anExpiredApiToken_isRejected() {
        apiToken(true, null, now(), null);
        assertThatThrownBy(() -> service.authenticateApiToken(PLAINTEXT))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.API_TOKEN_INVALID);
        verify(apiTokenRepository, never()).markUsed(any(), any());
    }

    @Test
    void anApiTokenOfADisabledAccount_isRejected() {
        apiToken(false, null, now().plusDays(30), null);
        assertThatThrownBy(() -> service.authenticateApiToken(PLAINTEXT))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.API_TOKEN_ACCOUNT_DISABLED);
    }

    @Test
    void anApiTokenOfALockedAccount_isRejectedAsLocked() {
        apiToken(true, OffsetDateTime.now().plusMinutes(10), now().plusDays(30), null);
        assertThatThrownBy(() -> service.authenticateApiToken(PLAINTEXT))
                .isInstanceOf(AccountLockedException.class);
    }

    @Test
    void theApiTokenIsLookedUpByItsHash_neverByItsPlaintext() {
        when(apiTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.authenticateApiToken(PLAINTEXT)).isInstanceOf(AuthException.class);
        verify(apiTokenRepository).findByTokenHash(eq(ApiTokens.hash(PLAINTEXT)));
        verify(apiTokenRepository, never()).findByTokenHash(eq(PLAINTEXT));
    }
}
