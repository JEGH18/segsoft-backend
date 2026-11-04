package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.RegisterRequest;
import co.icesi.pdgseg.dto.response.RegistrationResponse;
import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.RegistrationDisabledException;
import co.icesi.pdgseg.repository.RoleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Self-registration. A new account always gets the DEVELOPER role: AUDITOR and SECURITY_ADMIN
 * accounts are only created by the deployment (SEGSOFT_ACCOUNTS), never from the public API.
 * The account cannot log in until its email is verified with the link sent by
 * {@link EmailVerificationService}.
 */
@Service
public class RegistrationService {

    static final String USERNAME_TAKEN = "Ese nombre de usuario ya está en uso";
    static final String EMAIL_TAKEN = "Ese correo ya está registrado en otra cuenta";
    static final String CHECK_YOUR_EMAIL = "Te enviamos un enlace para verificar tu correo. Ábrelo para activar la cuenta.";

    /** Names that would look official or collide with the accounts of the deployment and the test guide. */
    static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "administrador", "administrator", "root", "system", "sistema", "soporte", "support",
            "seguridad", "security", "segsoft", "auditor", "dev", "usuario");

    /** Unique index of V34; tells a concurrent duplicate email apart from a duplicate username. */
    private static final String EMAIL_UNIQUE_INDEX = "ux_users_email_lower";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final AuditService auditService;
    private final RegistrationRateLimiter rateLimiter;
    private final boolean enabled;

    public RegistrationService(UserRepository userRepository,
                               RoleRepository roleRepository,
                               PasswordEncoder passwordEncoder,
                               EmailVerificationService emailVerificationService,
                               AuditService auditService,
                               RegistrationRateLimiter rateLimiter,
                               @Value("${auth.registration.enabled:true}") boolean enabled) {
        this.userRepository           = userRepository;
        this.roleRepository           = roleRepository;
        this.passwordEncoder          = passwordEncoder;
        this.emailVerificationService = emailVerificationService;
        this.auditService             = auditService;
        this.rateLimiter              = rateLimiter;
        this.enabled                  = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Creates a DEVELOPER account pending email verification and emails it the verification link. */
    @Transactional
    public RegistrationResponse register(RegisterRequest request, String ipAddress) {
        if (!enabled) {
            throw new RegistrationDisabledException();
        }
        rateLimiter.checkAttempt(ipAddress);
        emailVerificationService.requireDelivery();

        String username = normalize(request.username());
        String email = EmailVerificationService.normalizeEmail(request.email());
        if (RESERVED_USERNAMES.contains(username)) {
            throw new BusinessValidationException("Ese nombre de usuario está reservado. Elige otro.");
        }
        // Case-insensitive, so "Admin" cannot impersonate "admin".
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new ConflictException(USERNAME_TAKEN);
        }
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new ConflictException(EMAIL_TAKEN);
        }

        Role developer = roleRepository.findByName(RoleType.DEVELOPER)
                .orElseThrow(() -> new IllegalStateException("No existe el rol DEVELOPER"));
        rateLimiter.checkCreation();

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setEnabled(true);
        user.setRoles(new HashSet<>(Set.of(developer)));
        try {
            user = userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            // Another request registered the same name or email between the check and the insert.
            throw new ConflictException(isEmailDuplicate(e) ? EMAIL_TAKEN : USERNAME_TAKEN);
        }

        emailVerificationService.issue(user);
        auditService.record("USER_REGISTERED", username, ipAddress, Map.of("role", RoleType.DEVELOPER.name()));
        return new RegistrationResponse(username, email, CHECK_YOUR_EMAIL);
    }

    static String normalize(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean isEmailDuplicate(DataIntegrityViolationException e) {
        String detail = e.getMostSpecificCause().getMessage();
        return detail != null && detail.contains(EMAIL_UNIQUE_INDEX);
    }
}
