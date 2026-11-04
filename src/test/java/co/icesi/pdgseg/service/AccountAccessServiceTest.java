package co.icesi.pdgseg.service;

import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccountAccessServiceTest {

    private UserRepository userRepository;
    private AccountAccessService service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        service = new AccountAccessService(userRepository);
    }

    private void accountIs(Boolean enabled, OffsetDateTime lockedUntil, boolean verifiedEmail) {
        UserRepository.AccessState state = mock(UserRepository.AccessState.class);
        when(state.getEnabled()).thenReturn(enabled);
        when(state.getLockedUntil()).thenReturn(lockedUntil);
        when(state.getEmail()).thenReturn(verifiedEmail ? "alice@example.com" : null);
        when(state.getEmailVerifiedAt()).thenReturn(verifiedEmail ? OffsetDateTime.now().minusDays(1) : null);
        when(userRepository.findAccessStateByUsername("alice")).thenReturn(Optional.of(state));
    }

    @Test
    void anEnabledUnlockedAccount_passes() {
        accountIs(true, null, true);
        assertThatCode(() -> service.requireUsable("alice")).doesNotThrowAnyException();
    }

    @Test
    void anAccountWhoseLockIsOver_passes() {
        accountIs(true, OffsetDateTime.now().minusSeconds(1), true);
        assertThatCode(() -> service.requireUsable("alice")).doesNotThrowAnyException();
    }

    @Test
    void aLockedAccount_isRejectedWithTheMinutesLeft_andTheUnlockEmailHint() {
        accountIs(true, OffsetDateTime.now().plusMinutes(12).minusSeconds(30), true);

        assertThatThrownBy(() -> service.requireUsable("alice"))
                .isInstanceOfSatisfying(AccountLockedException.class,
                        e -> assertThat(e.getMinutesLeft()).isEqualTo(12))
                .hasMessage("La cuenta está bloqueada por demasiados intentos fallidos. Intenta de nuevo en "
                        + "12 minutos o usa el enlace que te enviamos por correo para desbloquearla.");
    }

    @Test
    void aDisabledAccount_isRejected() {
        accountIs(false, null, true);
        assertThatThrownBy(() -> service.requireUsable("alice"))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.SESSION_REVOKED);
    }

    @Test
    void aDeletedAccount_isRejected() {
        when(userRepository.findAccessStateByUsername("alice")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.requireUsable("alice"))
                .isInstanceOf(AuthException.class)
                .hasMessage(AccountAccessService.SESSION_REVOKED);
    }
}
