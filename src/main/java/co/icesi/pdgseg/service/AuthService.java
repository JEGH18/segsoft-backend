package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.LoginRequest;
import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.dto.response.UserResponse;
import co.icesi.pdgseg.entity.RefreshTokenBlacklist;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.repository.RefreshTokenBlacklistRepository;
import co.icesi.pdgseg.repository.UserRepository;
import co.icesi.pdgseg.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class AuthService {

    private static final String INVALID_CREDENTIALS  = "Credenciales inválidas";
    private static final int    MAX_FAILED_ATTEMPTS  = 5;
    private static final int    LOCK_MINUTES         = 30;
    private static final int    FAILURE_WINDOW_MIN   = 10;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenBlacklistRepository blacklistRepository;
    private final AuditService auditService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider,
                       RefreshTokenBlacklistRepository blacklistRepository,
                       AuditService auditService) {
        this.userRepository      = userRepository;
        this.passwordEncoder     = passwordEncoder;
        this.jwtTokenProvider    = jwtTokenProvider;
        this.blacklistRepository = blacklistRepository;
        this.auditService        = auditService;
    }

    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress) {
        User user = userRepository.findByUsername(request.username()).orElse(null);

        if (user == null) {
            auditService.record("LOGIN_FAILURE", request.username(), ipAddress,
                    Map.of("reason", "user_not_found"));
            throw new AuthException(INVALID_CREDENTIALS);
        }

        if (isLocked(user)) {
            auditService.record("ACCOUNT_LOCKED", user.getUsername(), ipAddress,
                    Map.of("locked_until", user.getLockedUntil().toString()));
            throw new AuthException(INVALID_CREDENTIALS);
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            registerFailedAttempt(user);
            userRepository.save(user);
            auditService.record("LOGIN_FAILURE", user.getUsername(), ipAddress,
                    Map.of("reason", "bad_password", "failed_attempts", user.getFailedAttempts()));
            throw new AuthException(INVALID_CREDENTIALS);
        }

        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setLastFailedAt(null);
        userRepository.save(user);

        List<String> roles = extractRoleNames(user);
        String accessToken  = jwtTokenProvider.generateAccessToken(user.getUsername(), roles);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getUsername());

        auditService.record("LOGIN_SUCCESS", user.getUsername(), ipAddress,
                Map.of("roles", roles));

        return new AuthResponse(accessToken, refreshToken, roles);
    }

    @Transactional
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
        return new UserResponse(user.getId(), user.getUsername(), extractRoleNames(user));
    }

    // ── private helpers ──────────────────────────────────────────────────────

    private boolean isLocked(User user) {
        return user.getLockedUntil() != null &&
               user.getLockedUntil().isAfter(OffsetDateTime.now());
    }

    private void registerFailedAttempt(User user) {
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
        }
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
