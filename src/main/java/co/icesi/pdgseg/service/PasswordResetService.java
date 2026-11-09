package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.PasswordResetToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.EmailDeliveryUnavailableException;
import co.icesi.pdgseg.exception.InvalidPasswordResetTokenException;
import co.icesi.pdgseg.repository.PasswordResetTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Password recovery: a single-use link emailed to the verified email of the account, with which a
 * new password is chosen. Changing it closes every open session and lifts a lock.
 */
@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    /** A new link is not sent if the previous one is younger than this, so the inbox cannot be flooded. */
    static final Duration REQUEST_COOLDOWN = Duration.ofMinutes(1);

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final RegistrationRateLimiter rateLimiter;
    private final AuthMailer mailer;
    private final ApplicationEventPublisher eventPublisher;
    private final Duration tokenTtl;

    public PasswordResetService(PasswordResetTokenRepository tokenRepository,
                                UserRepository userRepository,
                                PasswordEncoder passwordEncoder,
                                AuditService auditService,
                                RegistrationRateLimiter rateLimiter,
                                AuthMailer mailer,
                                ApplicationEventPublisher eventPublisher,
                                @Value("${auth.password-reset.token-ttl:PT30M}") Duration tokenTtl) {
        this.tokenRepository = tokenRepository;
        this.userRepository  = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService    = auditService;
        this.rateLimiter     = rateLimiter;
        this.mailer          = mailer;
        this.eventPublisher  = eventPublisher;
        this.tokenTtl        = tokenTtl;
    }

    /**
     * Emails a link to the account with this verified email, invalidating the previous ones.
     * Answers the same whether or not such an account exists, so it does not reveal which emails
     * are registered. Accounts without a verified email (such as those of SEGSOFT_ACCOUNTS) get
     * nothing.
     */
    @Transactional
    public void request(String email, String ipAddress) {
        rateLimiter.checkAttempt(ipAddress);
        if (!mailer.isAvailable()) {
            throw new EmailDeliveryUnavailableException();
        }

        OffsetDateTime now = OffsetDateTime.now();
        userRepository.findByEmailIgnoreCase(EmailVerificationService.normalizeEmail(email))
                .filter(user -> Boolean.TRUE.equals(user.getEnabled()) && user.getEmailVerifiedAt() != null)
                .filter(user -> !tokenRepository.existsByUserIdAndCreatedAtAfter(user.getId(),
                        now.minus(REQUEST_COOLDOWN)))
                .ifPresent(user -> {
                    tokenRepository.invalidatePending(user.getId(), now);
                    String token = OneTimeTokens.newToken();
                    tokenRepository.save(new PasswordResetToken(user, OneTimeTokens.hash(token), now.plus(tokenTtl)));
                    eventPublisher.publishEvent(new PasswordResetRequested(user.getUsername(), user.getEmail(), token,
                            tokenTtl.toMinutes()));
                    auditService.record("PASSWORD_RESET_REQUESTED", user.getUsername(), ipAddress, Map.of());
                });
    }

    /**
     * Consumes the link and sets {@code newPassword} (already checked against the password policy).
     * Every token issued before stops working, so all sessions end, and a lock from failed logins
     * is lifted: the link proves the email is the owner's. It does not start a session.
     */
    @Transactional
    public void reset(String token, String newPassword, String ipAddress) {
        PasswordResetToken stored = tokenRepository.findByTokenHash(OneTimeTokens.hash(token))
                .orElseThrow(InvalidPasswordResetTokenException::new);
        User user = stored.getUser();
        OffsetDateTime now = OffsetDateTime.now();
        if (!stored.isUsable(now) || !Boolean.TRUE.equals(user.getEnabled())) {
            throw new InvalidPasswordResetTokenException();
        }
        // Checked before using up the link, so it can be retried with another password.
        if (passwordEncoder.matches(newPassword, user.getPasswordHash())) {
            throw new BusinessValidationException("La contraseña nueva debe ser distinta de la actual.");
        }

        tokenRepository.invalidatePending(user.getId(), now);
        stored.setUsedAt(now);
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setTokenVersion(user.getTokenVersion() + 1);
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setLastFailedAt(null);
        tokenRepository.save(stored);
        userRepository.save(user);

        auditService.record("PASSWORD_RESET", user.getUsername(), ipAddress, Map.of("via", "email"));
        eventPublisher.publishEvent(new PasswordChanged(user.getUsername(), user.getEmail()));
    }

    /** Deletes the links that expired or were used more than a day ago. */
    @Transactional
    public void purgeExpired() {
        int tokens = tokenRepository.deleteFinishedBefore(OffsetDateTime.now().minusDays(1));
        if (tokens > 0) {
            log.info("Limpieza de enlaces de cambio de contraseña: enlaces={}", tokens);
        }
    }
}
