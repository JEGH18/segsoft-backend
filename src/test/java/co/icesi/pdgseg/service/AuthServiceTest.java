package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.LoginRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.exception.InvalidLoginException;
import co.icesi.pdgseg.repository.RefreshTokenBlacklistRepository;
import co.icesi.pdgseg.repository.UserRepository;
import co.icesi.pdgseg.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private RefreshTokenBlacklistRepository blacklistRepository;
    @Mock private AuditService auditService;
    @Mock private AccountUnlockService accountUnlockService;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(userRepository, passwordEncoder, jwtTokenProvider,
                blacklistRepository, auditService, accountUnlockService);
    }

    private User buildUser(String username) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername(username);
        user.setPasswordHash("hashed");
        user.setEnabled(true);
        user.setFailedAttempts(0);
        Role role = new Role();
        role.setName(RoleType.DEVELOPER);
        user.setRoles(Set.of(role));
        return user;
    }

    @Test
    void login_success_returnsAuthResponse() {
        User user = buildUser("alice");
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("pass", "hashed")).thenReturn(true);
        when(jwtTokenProvider.generateAccessToken(eq("alice"), anyList(), eq(0))).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken("alice", 0)).thenReturn("refresh");

        AuthResponse response = authService.login(new LoginRequest("alice", "pass"), "127.0.0.1");

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
        assertThat(response.tokenType()).isEqualTo("Bearer");
    }

    @Test
    void login_unknownUser_throwsWithGenericMessageAndTheLockWarning() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("ghost", "x"), "1.2.3.4"))
                .isInstanceOfSatisfying(InvalidLoginException.class, e -> assertThat(e.getAttemptsLeft()).isNull())
                .hasMessage("Credenciales inválidas. Después de 5 intentos fallidos, la cuenta se bloquea "
                        + "durante 30 minutos.");
    }

    @Test
    void login_wrongPassword_saysHowManyAttemptsAreLeft() {
        User user = buildUser("alice");
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "wrong"), "1.2.3.4"))
                .isInstanceOfSatisfying(InvalidLoginException.class, e -> assertThat(e.getAttemptsLeft()).isEqualTo(4))
                .hasMessage("Credenciales inválidas. Te quedan 4 intentos antes de que la cuenta se bloquee "
                        + "durante 30 minutos.");
    }

    @Test
    void login_fourthFailure_warnsThatOneAttemptIsLeft() {
        User user = buildUser("alice");
        user.setFailedAttempts(3);
        user.setLastFailedAt(OffsetDateTime.now().minusMinutes(1));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "wrong"), "1.2.3.4"))
                .hasMessageContaining("Te queda 1 intento antes");
        verifyNoInteractions(accountUnlockService);
    }

    @Test
    void login_fiveFailuresWithinWindow_locksAccount_andEmailsTheUnlockLink() {
        User user = buildUser("alice");
        user.setFailedAttempts(4);
        user.setLastFailedAt(OffsetDateTime.now().minusMinutes(2)); // within 10-min window
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
        when(accountUnlockService.issue(user, 5)).thenReturn(true);

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "bad"), "1.2.3.4"))
                .isInstanceOfSatisfying(AccountLockedException.class, e -> assertThat(e.getMinutesLeft()).isEqualTo(30))
                .hasMessage("Demasiados intentos fallidos: la cuenta quedó bloqueada durante 30 minutos. "
                        + "Te enviamos un correo con un enlace para desbloquearla.");

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getLockedUntil()).isNotNull();
        assertThat(saved.getLockedUntil()).isAfter(OffsetDateTime.now());
        verify(accountUnlockService).issue(user, 5);
        verify(auditService).record(eq("ACCOUNT_LOCKED"), eq("alice"), eq("1.2.3.4"), anyMap());
    }

    @Test
    void login_lockOfAnAccountWithoutEmail_doesNotMentionAnEmail() {
        User user = buildUser("admin");
        user.setFailedAttempts(4);
        user.setLastFailedAt(OffsetDateTime.now().minusMinutes(2));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
        when(accountUnlockService.issue(user, 5)).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("admin", "bad"), "1.2.3.4"))
                .isInstanceOf(AccountLockedException.class)
                .hasMessage("Demasiados intentos fallidos: la cuenta quedó bloqueada durante 30 minutos. "
                        + "Intenta de nuevo cuando termine el bloqueo.");
    }

    @Test
    void login_fiveFailuresOutsideWindow_doesNotLock() {
        User user = buildUser("alice");
        user.setFailedAttempts(4);
        user.setLastFailedAt(OffsetDateTime.now().minusMinutes(15)); // outside 10-min window
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "bad"), "1.2.3.4"))
                .isInstanceOf(InvalidLoginException.class);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        // Counter was reset then incremented to 1 — not locked
        assertThat(captor.getValue().getLockedUntil()).isNull();
        assertThat(captor.getValue().getFailedAttempts()).isEqualTo(1);
    }

    @Test
    void login_lockedAccount_saysHowLongItStaysLocked_withoutCheckingThePassword() {
        User user = buildUser("alice");
        user.setEmail("alice@example.com");
        user.setEmailVerifiedAt(OffsetDateTime.now().minusDays(1));
        user.setLockedUntil(OffsetDateTime.now().plusMinutes(15).minusSeconds(30));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "x"), "1.2.3.4"))
                .isInstanceOfSatisfying(AccountLockedException.class, e -> assertThat(e.getMinutesLeft()).isEqualTo(15))
                .hasMessage("La cuenta está bloqueada por demasiados intentos fallidos. Intenta de nuevo en "
                        + "15 minutos o usa el enlace que te enviamos por correo para desbloquearla.");
        verifyNoInteractions(passwordEncoder, accountUnlockService);
    }

    @Test
    void refresh_validToken_rotatesRefreshToken() {
        User user = buildUser("alice");
        when(jwtTokenProvider.validateToken("old-refresh")).thenReturn(true);
        when(blacklistRepository.existsById(anyString())).thenReturn(false);
        when(jwtTokenProvider.extractUsername("old-refresh")).thenReturn("alice");
        when(jwtTokenProvider.extractExpiry("old-refresh"))
                .thenReturn(new Date(System.currentTimeMillis() + 3_600_000));
        when(userRepository.findByUsernameAndEnabledTrue("alice")).thenReturn(Optional.of(user));
        when(jwtTokenProvider.generateAccessToken(eq("alice"), anyList(), eq(0))).thenReturn("new-access");
        when(jwtTokenProvider.generateRefreshToken("alice", 0)).thenReturn("new-refresh");

        AuthResponse response = authService.refresh("old-refresh");

        assertThat(response.accessToken()).isEqualTo("new-access");
        assertThat(response.refreshToken()).isEqualTo("new-refresh"); // rotated
        // old token invalidated (an insert that tolerates a concurrent rotation of the same token)
        verify(blacklistRepository).insertIgnoreConflict(matches("[0-9a-f]{64}"), any(OffsetDateTime.class));
    }

    @Test
    void refresh_lockedAccount_isRejectedWithoutRevokingTheToken() {
        User user = buildUser("alice");
        user.setLockedUntil(OffsetDateTime.now().plusMinutes(10));
        when(jwtTokenProvider.validateToken("old-refresh")).thenReturn(true);
        when(blacklistRepository.existsById(anyString())).thenReturn(false);
        when(jwtTokenProvider.extractUsername("old-refresh")).thenReturn("alice");
        when(userRepository.findByUsernameAndEnabledTrue("alice")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.refresh("old-refresh"))
                .isInstanceOfSatisfying(AccountLockedException.class, e -> assertThat(e.getMinutesLeft()).isEqualTo(10));

        verify(blacklistRepository, never()).insertIgnoreConflict(anyString(), any());
        verify(jwtTokenProvider, never()).generateAccessToken(anyString(), anyList(), anyInt());
    }

    @Test
    void refresh_aTokenFromBeforeThePasswordChanged_isRejected() {
        User user = buildUser("alice");
        user.setTokenVersion(1);
        when(jwtTokenProvider.validateToken("old-refresh")).thenReturn(true);
        when(blacklistRepository.existsById(anyString())).thenReturn(false);
        when(jwtTokenProvider.extractUsername("old-refresh")).thenReturn("alice");
        when(jwtTokenProvider.extractTokenVersion("old-refresh")).thenReturn(0);
        when(userRepository.findByUsernameAndEnabledTrue("alice")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.refresh("old-refresh")).isInstanceOf(AuthException.class);

        verify(jwtTokenProvider, never()).generateAccessToken(anyString(), anyList(), anyInt());
    }

    @Test
    void startSession_putsTheCurrentTokenVersionInBothTokens() {
        User user = buildUser("alice");
        user.setTokenVersion(4);
        when(jwtTokenProvider.generateAccessToken(eq("alice"), anyList(), eq(4))).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken("alice", 4)).thenReturn("refresh");

        AuthResponse response = authService.startSession(user);

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
    }

    @Test
    void refresh_blacklistedToken_throwsAuthException() {
        when(jwtTokenProvider.validateToken("blacklisted")).thenReturn(true);
        when(blacklistRepository.existsById(anyString())).thenReturn(true);

        assertThatThrownBy(() -> authService.refresh("blacklisted"))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void logout_validToken_savesToBlacklist() {
        when(jwtTokenProvider.validateToken("refresh-tk")).thenReturn(true);
        when(jwtTokenProvider.extractExpiry("refresh-tk"))
                .thenReturn(new Date(System.currentTimeMillis() + 3_600_000));
        when(jwtTokenProvider.extractUsername("refresh-tk")).thenReturn("alice");

        authService.logout("refresh-tk");

        // Only the SHA-256 of the token is stored.
        verify(blacklistRepository).insertIgnoreConflict(matches("[0-9a-f]{64}"), any(OffsetDateTime.class));
    }
}
