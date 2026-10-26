package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.RegisterRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.RegistrationDisabledException;
import co.icesi.pdgseg.exception.TooManyRequestsException;
import co.icesi.pdgseg.repository.RoleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Map;
import java.util.Optional;

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

class RegistrationServiceTest {

    private static final String STRONG_PASSWORD = "Segsoft-Prueba-2026!";

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private AuthService authService;
    private AuditService auditService;
    private RegistrationRateLimiter rateLimiter;
    private Role developer;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        roleRepository = mock(RoleRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        authService = mock(AuthService.class);
        auditService = mock(AuditService.class);
        rateLimiter = mock(RegistrationRateLimiter.class);
        developer = new Role();
        developer.setName(RoleType.DEVELOPER);

        when(roleRepository.findByName(RoleType.DEVELOPER)).thenReturn(Optional.of(developer));
        when(passwordEncoder.encode(STRONG_PASSWORD)).thenReturn("hash");
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(authService.startSession(any(User.class)))
                .thenReturn(new AuthResponse("access", "refresh", List.of("DEVELOPER")));
    }

    private RegistrationService service(boolean enabled) {
        return new RegistrationService(userRepository, roleRepository, passwordEncoder, authService,
                auditService, rateLimiter, enabled);
    }

    @Test
    void register_createsALowercaseDeveloperAccountWithAHashedPassword_andStartsItsSession() {
        AuthResponse auth = service(true).register(new RegisterRequest("  Juan.Gomez ", STRONG_PASSWORD), "10.0.0.1");

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(saved.capture());
        User user = saved.getValue();
        assertThat(user.getUsername()).isEqualTo("juan.gomez");
        assertThat(user.getPasswordHash()).isEqualTo("hash");
        assertThat(user.getEnabled()).isTrue();
        assertThat(user.getRoles()).extracting(Role::getName).containsExactly(RoleType.DEVELOPER);

        assertThat(auth.accessToken()).isEqualTo("access");
        verify(authService).startSession(user);
        verify(auditService).record("USER_REGISTERED", "juan.gomez", "10.0.0.1", Map.of("role", "DEVELOPER"));
    }

    @Test
    void register_rejectsAnExistingUsernameIgnoringCase() {
        when(userRepository.existsByUsernameIgnoreCase("auditora")).thenReturn(true);

        assertThatThrownBy(() -> service(true).register(new RegisterRequest("AUDITORA", STRONG_PASSWORD), "ip"))
                .isInstanceOf(ConflictException.class)
                .hasMessage(RegistrationService.USERNAME_TAKEN);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void register_turnsAConcurrentDuplicateIntoAConflict() {
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(new DataIntegrityViolationException("unique"));

        assertThatThrownBy(() -> service(true).register(new RegisterRequest("nuevo", STRONG_PASSWORD), "ip"))
                .isInstanceOf(ConflictException.class);
        verify(auditService, never()).record(eq("USER_REGISTERED"), anyString(), anyString(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"admin", "Admin", "root", "segsoft", "auditor", "dev", "usuario"})
    void register_rejectsReservedUsernames(String username) {
        assertThatThrownBy(() -> service(true).register(new RegisterRequest(username, STRONG_PASSWORD), "ip"))
                .isInstanceOf(BusinessValidationException.class)
                .hasMessageContaining("reservado");
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void register_failsWhenRegistrationIsDisabled_beforeCountingTheAttempt() {
        assertThatThrownBy(() -> service(false).register(new RegisterRequest("nuevo", STRONG_PASSWORD), "ip"))
                .isInstanceOf(RegistrationDisabledException.class);
        verifyNoInteractions(rateLimiter, userRepository, passwordEncoder);
    }

    @Test
    void register_stopsBeforeHashingWhenTheIpExceedsItsLimit() {
        doThrow(new TooManyRequestsException("limite")).when(rateLimiter).checkAttempt("ip");

        assertThatThrownBy(() -> service(true).register(new RegisterRequest("nuevo", STRONG_PASSWORD), "ip"))
                .isInstanceOf(TooManyRequestsException.class);
        verifyNoInteractions(passwordEncoder);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void register_doesNotCountRejectedNamesAgainstTheGlobalCap() {
        when(userRepository.existsByUsernameIgnoreCase("ocupado")).thenReturn(true);

        assertThatThrownBy(() -> service(true).register(new RegisterRequest("ocupado", STRONG_PASSWORD), "ip"))
                .isInstanceOf(ConflictException.class);
        verify(rateLimiter).checkAttempt("ip");
        verify(rateLimiter, never()).checkCreation();
    }
}
