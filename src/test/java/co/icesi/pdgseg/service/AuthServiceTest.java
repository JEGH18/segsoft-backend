package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.LoginRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.entity.RefreshTokenBlacklist;
import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.exception.AuthException;
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

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(userRepository, passwordEncoder, jwtTokenProvider,
                blacklistRepository, auditService);
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
        when(jwtTokenProvider.generateAccessToken(eq("alice"), anyList())).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken("alice")).thenReturn("refresh");

        AuthResponse response = authService.login(new LoginRequest("alice", "pass"), "127.0.0.1");

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
        assertThat(response.tokenType()).isEqualTo("Bearer");
    }

    @Test
    void login_unknownUser_throwsWithGenericMessage() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("ghost", "x"), "1.2.3.4"))
                .isInstanceOf(AuthException.class)
                .hasMessage("Credenciales inválidas");
    }

    @Test
    void login_wrongPassword_throwsWithGenericMessage() {
        User user = buildUser("alice");
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "wrong"), "1.2.3.4"))
                .isInstanceOf(AuthException.class)
                .hasMessage("Credenciales inválidas");
    }

    @Test
    void login_fiveFailuresWithinWindow_locksAccount() {
        User user = buildUser("alice");
        user.setFailedAttempts(4);
        user.setLastFailedAt(OffsetDateTime.now().minusMinutes(2)); // within 10-min window
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "bad"), "1.2.3.4"))
                .isInstanceOf(AuthException.class);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getLockedUntil()).isNotNull();
        assertThat(saved.getLockedUntil()).isAfter(OffsetDateTime.now());
    }

    @Test
    void login_fiveFailuresOutsideWindow_doesNotLock() {
        User user = buildUser("alice");
        user.setFailedAttempts(4);
        user.setLastFailedAt(OffsetDateTime.now().minusMinutes(15)); // outside 10-min window
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "bad"), "1.2.3.4"))
                .isInstanceOf(AuthException.class);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        // Counter was reset then incremented to 1 — not locked
        assertThat(captor.getValue().getLockedUntil()).isNull();
        assertThat(captor.getValue().getFailedAttempts()).isEqualTo(1);
    }

    @Test
    void login_lockedAccount_throwsGenericMessage() {
        User user = buildUser("alice");
        user.setLockedUntil(OffsetDateTime.now().plusMinutes(15));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "x"), "1.2.3.4"))
                .isInstanceOf(AuthException.class)
                .hasMessage("Credenciales inválidas");
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
        when(jwtTokenProvider.generateAccessToken(eq("alice"), anyList())).thenReturn("new-access");
        when(jwtTokenProvider.generateRefreshToken("alice")).thenReturn("new-refresh");

        AuthResponse response = authService.refresh("old-refresh");

        assertThat(response.accessToken()).isEqualTo("new-access");
        assertThat(response.refreshToken()).isEqualTo("new-refresh"); // rotated
        verify(blacklistRepository).save(any(RefreshTokenBlacklist.class)); // old token invalidated
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

        ArgumentCaptor<RefreshTokenBlacklist> captor = ArgumentCaptor.forClass(RefreshTokenBlacklist.class);
        verify(blacklistRepository).save(captor.capture());
        assertThat(captor.getValue().getTokenHash()).isNotBlank();
    }
}
