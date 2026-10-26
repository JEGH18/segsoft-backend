package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.RegisterRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
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
 */
@Service
public class RegistrationService {

    static final String USERNAME_TAKEN = "Ese nombre de usuario ya está en uso";

    /** Names that would look official or collide with the accounts of the deployment and the test guide. */
    static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "administrador", "administrator", "root", "system", "sistema", "soporte", "support",
            "seguridad", "security", "segsoft", "auditor", "dev", "usuario");

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthService authService;
    private final AuditService auditService;
    private final RegistrationRateLimiter rateLimiter;
    private final boolean enabled;

    public RegistrationService(UserRepository userRepository,
                               RoleRepository roleRepository,
                               PasswordEncoder passwordEncoder,
                               AuthService authService,
                               AuditService auditService,
                               RegistrationRateLimiter rateLimiter,
                               @Value("${auth.registration.enabled:true}") boolean enabled) {
        this.userRepository  = userRepository;
        this.roleRepository  = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authService     = authService;
        this.auditService    = auditService;
        this.rateLimiter     = rateLimiter;
        this.enabled         = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Creates a DEVELOPER account and starts its session. */
    @Transactional
    public AuthResponse register(RegisterRequest request, String ipAddress) {
        if (!enabled) {
            throw new RegistrationDisabledException();
        }
        rateLimiter.checkAttempt(ipAddress);

        String username = normalize(request.username());
        if (RESERVED_USERNAMES.contains(username)) {
            throw new BusinessValidationException("Ese nombre de usuario está reservado. Elige otro.");
        }
        // Case-insensitive, so "Admin" cannot impersonate "admin".
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new ConflictException(USERNAME_TAKEN);
        }

        Role developer = roleRepository.findByName(RoleType.DEVELOPER)
                .orElseThrow(() -> new IllegalStateException("No existe el rol DEVELOPER"));
        rateLimiter.checkCreation();

        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setEnabled(true);
        user.setRoles(new HashSet<>(Set.of(developer)));
        try {
            user = userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            // Another request registered the same name between the check and the insert.
            throw new ConflictException(USERNAME_TAKEN);
        }

        auditService.record("USER_REGISTERED", username, ipAddress, Map.of("role", RoleType.DEVELOPER.name()));
        return authService.startSession(user);
    }

    static String normalize(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }
}
