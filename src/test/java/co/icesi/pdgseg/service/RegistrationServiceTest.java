package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.RegisterRequest;
import co.icesi.pdgseg.dto.response.RegistrationResponse;
import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.EmailDeliveryUnavailableException;
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

import java.sql.SQLException;
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
    private static final String EMAIL = "juan@example.com";

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private EmailVerificationService emailVerificationService;
    private AuditService auditService;
    private RegistrationRateLimiter rateLimiter;
    private Role developer;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        roleRepository = mock(RoleRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        emailVerificationService = mock(EmailVerificationService.class);
        auditService = mock(AuditService.class);
        rateLimiter = mock(RegistrationRateLimiter.class);
        developer = new Role();
        developer.setName(RoleType.DEVELOPER);

        when(roleRepository.findByName(RoleType.DEVELOPER)).thenReturn(Optional.of(developer));
        when(passwordEncoder.encode(STRONG_PASSWORD)).thenReturn("hash");
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    private RegistrationService service(boolean enabled) {
        return new RegistrationService(userRepository, roleRepository, passwordEncoder, emailVerificationService,
                auditService, rateLimiter, enabled);
    }

    private static RegisterRequest request(String username) {
        return new RegisterRequest(username, EMAIL, STRONG_PASSWORD);
    }

    private static DataIntegrityViolationException duplicate(String constraint) {
        return new DataIntegrityViolationException("unique",
                new SQLException("duplicate key value violates unique constraint \"" + constraint + "\""));
    }

    @Test
    void register_createsAnUnverifiedLowercaseDeveloperAccount_andSendsTheLink() {
        RegistrationResponse response = service(true).register(
                new RegisterRequest("  Juan.Gomez ", "  Juan@Example.COM ", STRONG_PASSWORD), "10.0.0.1");

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(saved.capture());
        User user = saved.getValue();
        assertThat(user.getUsername()).isEqualTo("juan.gomez");
        assertThat(user.getEmail()).isEqualTo("juan@example.com");
        assertThat(user.getEmailVerifiedAt()).isNull();
        assertThat(user.isEmailPendingVerification()).isTrue();
        assertThat(user.getPasswordHash()).isEqualTo("hash");
        assertThat(user.getEnabled()).isTrue();
        assertThat(user.getRoles()).extracting(Role::getName).containsExactly(RoleType.DEVELOPER);

        verify(emailVerificationService).issue(user);
        assertThat(response.username()).isEqualTo("juan.gomez");
        assertThat(response.email()).isEqualTo("juan@example.com");
        assertThat(response.message()).isEqualTo(RegistrationService.CHECK_YOUR_EMAIL);
        verify(auditService).record("USER_REGISTERED", "juan.gomez", "10.0.0.1", Map.of("role", "DEVELOPER"));
    }

    @Test
    void register_rejectsAnExistingUsernameIgnoringCase() {
        when(userRepository.existsByUsernameIgnoreCase("auditora")).thenReturn(true);

        assertThatThrownBy(() -> service(true).register(request("AUDITORA"), "ip"))
                .isInstanceOf(ConflictException.class)
                .hasMessage(RegistrationService.USERNAME_TAKEN);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void register_rejectsAnEmailThatAnotherAccountUses_ignoringCase() {
        when(userRepository.existsByEmailIgnoreCase("juan@example.com")).thenReturn(true);

        assertThatThrownBy(() -> service(true).register(
                new RegisterRequest("otro", "JUAN@example.com", STRONG_PASSWORD), "ip"))
                .isInstanceOf(ConflictException.class)
                .hasMessage(RegistrationService.EMAIL_TAKEN);
        verify(userRepository, never()).saveAndFlush(any());
        verify(rateLimiter, never()).checkCreation();
    }

    @Test
    void register_turnsAConcurrentDuplicateUsernameIntoAConflict() {
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(duplicate("users_username_key"));

        assertThatThrownBy(() -> service(true).register(request("nuevo"), "ip"))
                .isInstanceOf(ConflictException.class)
                .hasMessage(RegistrationService.USERNAME_TAKEN);
        verify(auditService, never()).record(eq("USER_REGISTERED"), anyString(), anyString(), any());
        verify(emailVerificationService, never()).issue(any());
    }

    @Test
    void register_turnsAConcurrentDuplicateEmailIntoAConflict() {
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(duplicate("ux_users_email_lower"));

        assertThatThrownBy(() -> service(true).register(request("nuevo"), "ip"))
                .isInstanceOf(ConflictException.class)
                .hasMessage(RegistrationService.EMAIL_TAKEN);
    }

    @ParameterizedTest
    @ValueSource(strings = {"admin", "Admin", "root", "segsoft", "auditor", "dev", "usuario"})
    void register_rejectsReservedUsernames(String username) {
        assertThatThrownBy(() -> service(true).register(request(username), "ip"))
                .isInstanceOf(BusinessValidationException.class)
                .hasMessageContaining("reservado");
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void register_failsWhenRegistrationIsDisabled_beforeCountingTheAttempt() {
        assertThatThrownBy(() -> service(false).register(request("nuevo"), "ip"))
                .isInstanceOf(RegistrationDisabledException.class);
        verifyNoInteractions(rateLimiter, userRepository, passwordEncoder, emailVerificationService);
    }

    @Test
    void register_failsBeforeStoringAnythingWhenNoEmailCanBeSent() {
        doThrow(new EmailDeliveryUnavailableException()).when(emailVerificationService).requireDelivery();

        assertThatThrownBy(() -> service(true).register(request("nuevo"), "ip"))
                .isInstanceOf(EmailDeliveryUnavailableException.class);
        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @Test
    void register_stopsBeforeHashingWhenTheIpExceedsItsLimit() {
        doThrow(new TooManyRequestsException("limite")).when(rateLimiter).checkAttempt("ip");

        assertThatThrownBy(() -> service(true).register(request("nuevo"), "ip"))
                .isInstanceOf(TooManyRequestsException.class);
        verifyNoInteractions(passwordEncoder);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void register_doesNotCountRejectedNamesAgainstTheGlobalCap() {
        when(userRepository.existsByUsernameIgnoreCase("ocupado")).thenReturn(true);

        assertThatThrownBy(() -> service(true).register(request("ocupado"), "ip"))
                .isInstanceOf(ConflictException.class);
        verify(rateLimiter).checkAttempt("ip");
        verify(rateLimiter, never()).checkCreation();
    }
}
