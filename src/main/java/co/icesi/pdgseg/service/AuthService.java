package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.LoginRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.dto.response.UserResponse;
import co.icesi.pdgseg.entity.RefreshTokenBlacklist;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.exception.EmailNotVerifiedException;
import co.icesi.pdgseg.exception.InvalidLoginException;
import co.icesi.pdgseg.repository.RefreshTokenBlacklistRepository;
import co.icesi.pdgseg.repository.UserRepository;
import co.icesi.pdgseg.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class AuthService {

    private static final String INVALID_CREDENTIALS  = "Credenciales inválidas";
    static final int            MAX_FAILED_ATTEMPTS  = 5;
    static final int            LOCK_MINUTES         = 30;
    private static final int    FAILURE_WINDOW_MIN   = 10;

    /** For an unknown user or a disabled account, which have no attempt count to show. */
    static final String LOGIN_FAILED = INVALID_CREDENTIALS + ". Después de " + MAX_FAILED_ATTEMPTS
            + " intentos fallidos, la cuenta se bloquea durante " + LOCK_MINUTES + " minutos.";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenBlacklistRepository blacklistRepository;
    private final AuditService auditService;
    private final AccountUnlockService accountUnlockService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider,
                       RefreshTokenBlacklistRepository blacklistRepository,
                       AuditService auditService,
                       AccountUnlockService accountUnlockService) {
        this.userRepository       = userRepository;
        this.passwordEncoder      = passwordEncoder;
        this.jwtTokenProvider     = jwtTokenProvider;
        this.blacklistRepository  = blacklistRepository;
        this.auditService         = auditService;
        this.accountUnlockService = accountUnlockService;
    }

    /**
     * A rejected login throws, but what it stored before throwing (the failed attempt, the lock, the
     * unlock link and the audit) must be committed: rolling them back would leave brute force
     * unlimited and unaudited.
     */
    @Transactional(noRollbackFor = {AuthException.class, AccountLockedException.class,
            EmailNotVerifiedException.class})
    public AuthResponse login(LoginRequest request, String ipAddress) {
        User user = userRepository.findByUsername(request.username()).orElse(null);

        if (user == null) {
            auditService.record("LOGIN_FAILURE", request.username(), ipAddress,
                    Map.of("reason", "user_not_found"));
            throw new InvalidLoginException(LOGIN_FAILED, null);
        }

        // Disabled accounts (e.g. demo accounts disabled by ProdAccountsInitializer) cannot log in.
        if (!Boolean.TRUE.equals(user.getEnabled())) {
            auditService.record("LOGIN_FAILURE", user.getUsername(), ipAddress,
                    Map.of("reason", "account_disabled"));
            throw new InvalidLoginException(LOGIN_FAILED, null);
        }

        if (isLocked(user)) {
            auditService.record("LOGIN_FAILURE", user.getUsername(), ipAddress,
                    Map.of("reason", "account_locked", "locked_until", user.getLockedUntil().toString()));
            throw stillLocked(user);
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            boolean lockedNow = registerFailedAttempt(user);
            userRepository.save(user);
            if (lockedNow) {
                auditService.record("ACCOUNT_LOCKED", user.getUsername(), ipAddress,
                        Map.of("reason", "too_many_failures", "locked_until", user.getLockedUntil().toString()));
                boolean emailed = accountUnlockService.issue(user, MAX_FAILED_ATTEMPTS);
                throw new AccountLockedException(justLockedMessage(emailed), LOCK_MINUTES);
            }
            auditService.record("LOGIN_FAILURE", user.getUsername(), ipAddress,
                    Map.of("reason", "bad_password", "failed_attempts", user.getFailedAttempts()));
            int attemptsLeft = MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
            throw new InvalidLoginException(attemptsLeftMessage(attemptsLeft), attemptsLeft);
        }

        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setLastFailedAt(null);
        userRepository.save(user);

        // Checked after the password, so it does not reveal which accounts are pending verification.
        if (user.isEmailPendingVerification()) {
            auditService.record("LOGIN_FAILURE", user.getUsername(), ipAddress,
                    Map.of("reason", "email_not_verified"));
            throw new EmailNotVerifiedException(user.getEmail());
        }

        AuthResponse auth = startSession(user);
        auditService.record("LOGIN_SUCCESS", user.getUsername(), ipAddress,
                Map.of("roles", auth.roles()));
        return auth;
    }

    /** Issues the access and refresh tokens of a new session for {@code user}. */
    public AuthResponse startSession(User user) {
        List<String> roles = extractRoleNames(user);
        String accessToken  = jwtTokenProvider.generateAccessToken(user.getUsername(), roles);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getUsername());
        return new AuthResponse(accessToken, refreshToken, roles);
    }

    /**
     * A locked account cannot renew a session started before the lock; the refresh token is not
     * revoked, so the session goes on once the lock ends or the account is unlocked.
     */
    @Transactional(noRollbackFor = AccountLockedException.class)
    public AuthResponse refresh(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new AuthException(INVALID_CREDENTIALS);
        }

        String tokenHash = sha256(refreshToken);
        if (blacklistRepository.existsById(tokenHash)) {
            throw new AuthException(INVALID_CREDENTIALS);
        }

        String username = jwtTokenProvider.extractUsername(refreshToken);
        User user = userRepository.findByUsernameAndEnabledTrue(username)
                .orElseThrow(() -> new AuthException(INVALID_CREDENTIALS));
        if (isLocked(user)) {
            auditService.record("LOGIN_FAILURE", username, null,
                    Map.of("reason", "account_locked", "via", "refresh"));
            throw stillLocked(user);
        }

        // Rotation: invalidate old refresh token, issue a new one
        Date expiry = jwtTokenProvider.extractExpiry(refreshToken);
        blacklistRepository.insertIgnoreConflict(
                tokenHash, expiry.toInstant().atOffset(ZoneOffset.UTC));

        List<String> roles      = extractRoleNames(user);
        String newAccessToken   = jwtTokenProvider.generateAccessToken(username, roles);
        String newRefreshToken  = jwtTokenProvider.generateRefreshToken(username);

        return new AuthResponse(newAccessToken, newRefreshToken, roles);
    }

    @Transactional
    public void logout(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            return;
        }
        String tokenHash = sha256(refreshToken);
        Date expiry = jwtTokenProvider.extractExpiry(refreshToken);
        blacklistRepository.insertIgnoreConflict(
                tokenHash, expiry.toInstant().atOffset(ZoneOffset.UTC));

        String username = jwtTokenProvider.extractUsername(refreshToken);
        auditService.record("LOGOUT", username, null, Map.of());
    }

    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AuthException(INVALID_CREDENTIALS));
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail(), extractRoleNames(user));
    }

    // ── private helpers ──────────────────────────────────────────────────────

    static boolean isLocked(User user) {
        return isLocked(user.getLockedUntil());
    }

    static boolean isLocked(OffsetDateTime lockedUntil) {
        return lockedUntil != null && lockedUntil.isAfter(OffsetDateTime.now());
    }

    /**
     * The rejection for any way into a locked account: login, session renewal, email link or an
     * access token issued before the lock.
     */
    static AccountLockedException stillLocked(User user) {
        return stillLocked(user.getLockedUntil(), hasVerifiedEmail(user.getEmail(), user.getEmailVerifiedAt()));
    }

    static AccountLockedException stillLocked(OffsetDateTime lockedUntil, boolean emailed) {
        long minutesLeft = minutesLeft(lockedUntil);
        return new AccountLockedException(stillLockedMessage(minutesLeft, emailed), minutesLeft);
    }

    /** Minutes until the lock ends, rounded up, so it never says 0 while still locked. */
    private static long minutesLeft(OffsetDateTime lockedUntil) {
        long seconds = Duration.between(OffsetDateTime.now(), lockedUntil).getSeconds();
        return Math.max(1, (seconds + 59) / 60);
    }

    static boolean hasVerifiedEmail(String email, OffsetDateTime emailVerifiedAt) {
        return email != null && emailVerifiedAt != null;
    }

    static String attemptsLeftMessage(int attemptsLeft) {
        return INVALID_CREDENTIALS + ". " + (attemptsLeft == 1 ? "Te queda 1 intento" : "Te quedan " + attemptsLeft
                + " intentos") + " antes de que la cuenta se bloquee durante " + LOCK_MINUTES + " minutos.";
    }

    static String justLockedMessage(boolean emailed) {
        return "Demasiados intentos fallidos: la cuenta quedó bloqueada durante " + LOCK_MINUTES + " minutos. "
                + (emailed ? "Te enviamos un correo con un enlace para desbloquearla."
                           : "Intenta de nuevo cuando termine el bloqueo.");
    }

    static String stillLockedMessage(long minutesLeft, boolean emailed) {
        return "La cuenta está bloqueada por demasiados intentos fallidos. Intenta de nuevo en " + minutesLeft
                + (minutesLeft == 1 ? " minuto" : " minutos")
                + (emailed ? " o usa el enlace que te enviamos por correo para desbloquearla." : ".");
    }

    /** Counts a failed attempt; returns whether it locked the account. */
    private boolean registerFailedAttempt(User user) {
        OffsetDateTime now = OffsetDateTime.now();

        // Reset counter if last failure was outside the 10-minute window
        if (user.getLastFailedAt() != null &&
                user.getLastFailedAt().isBefore(now.minusMinutes(FAILURE_WINDOW_MIN))) {
            user.setFailedAttempts(0);
        }

        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);
        user.setLastFailedAt(now);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(now.plusMinutes(LOCK_MINUTES));
            user.setFailedAttempts(0);
            user.setLastFailedAt(null);
            return true;
        }
        return false;
    }

    private List<String> extractRoleNames(User user) {
        return user.getRoles().stream()
                .map(r -> r.getName().name())
                .toList();
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
