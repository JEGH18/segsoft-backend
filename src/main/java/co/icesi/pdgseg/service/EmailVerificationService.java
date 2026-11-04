package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.AuthResponse;
import co.icesi.pdgseg.entity.EmailVerificationToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.EmailDeliveryUnavailableException;
import co.icesi.pdgseg.exception.InvalidVerificationTokenException;
import co.icesi.pdgseg.repository.EmailVerificationTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;

/**
 * Verification of the email of self-registered accounts: issues single-use links, consumes them
 * and purges the registrations that were never verified.
 */
@Service
public class EmailVerificationService {

    private static final Logger log = LoggerFactory.getLogger(EmailVerificationService.class);

    /** A new link is not sent if the previous one is younger than this, so the inbox cannot be flooded. */
    static final Duration RESEND_COOLDOWN = Duration.ofMinutes(1);
    private static final int TOKEN_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final AuthService authService;
    private final AuditService auditService;
    private final RegistrationRateLimiter rateLimiter;
    private final VerificationMailer mailer;
    private final ApplicationEventPublisher eventPublisher;
    private final Duration tokenTtl;
    private final Duration unverifiedRetention;

    public EmailVerificationService(EmailVerificationTokenRepository tokenRepository,
                                    UserRepository userRepository,
                                    AuthService authService,
                                    AuditService auditService,
                                    RegistrationRateLimiter rateLimiter,
                                    VerificationMailer mailer,
                                    ApplicationEventPublisher eventPublisher,
                                    @Value("${auth.email-verification.token-ttl:PT24H}") Duration tokenTtl,
                                    @Value("${auth.email-verification.unverified-retention:P7D}") Duration unverifiedRetention) {
        this.tokenRepository     = tokenRepository;
        this.userRepository      = userRepository;
        this.authService         = authService;
        this.auditService        = auditService;
        this.rateLimiter         = rateLimiter;
        this.mailer              = mailer;
        this.eventPublisher      = eventPublisher;
        this.tokenTtl            = tokenTtl;
        this.unverifiedRetention = unverifiedRetention;
    }

    /** Fails before anything is stored when no email could be sent. */
    public void requireDelivery() {
        if (!mailer.isAvailable()) {
            throw new EmailDeliveryUnavailableException();
        }
    }

    /**
     * Stores a new link for {@code user}, invalidating the previous ones, and has it emailed once
     * the caller's transaction commits.
     */
    @Transactional
    public void issue(User user) {
        OffsetDateTime now = OffsetDateTime.now();
        tokenRepository.invalidatePending(user.getId(), now);
        String token = newToken();
        tokenRepository.save(new EmailVerificationToken(user, ReportChecksum.sha256Hex(token), now.plus(tokenTtl)));
        eventPublisher.publishEvent(new VerificationEmailRequested(user.getUsername(), user.getEmail(), token));
    }

    /** Consumes the link, marks the email as verified and starts the session of its account. */
    @Transactional
    public AuthResponse verify(String token, String ipAddress) {
        EmailVerificationToken stored = tokenRepository.findByTokenHash(ReportChecksum.sha256Hex(token.trim()))
                .orElseThrow(InvalidVerificationTokenException::new);
        User user = stored.getUser();
        OffsetDateTime now = OffsetDateTime.now();

        if (!stored.isUsable(now) || !Boolean.TRUE.equals(user.getEnabled())) {
            if (stored.getUsedAt() != null && user.getEmailVerifiedAt() != null) {
                throw new InvalidVerificationTokenException("Tu correo ya está verificado. Inicia sesión.");
            }
            throw new InvalidVerificationTokenException();
        }

        stored.setUsedAt(now);
        user.setEmailVerifiedAt(now);
        tokenRepository.save(stored);
        userRepository.save(user);

        auditService.record("EMAIL_VERIFIED", user.getUsername(), ipAddress, Map.of());
        return authService.startSession(user);
    }

    /**
     * Sends a new link to an account whose email is still unverified. Answers the same whether or
     * not such an account exists.
     */
    @Transactional
    public void resend(String email, String ipAddress) {
        rateLimiter.checkAttempt(ipAddress);
        requireDelivery();

        OffsetDateTime cooldownStart = OffsetDateTime.now().minus(RESEND_COOLDOWN);
        userRepository.findByEmailIgnoreCase(normalizeEmail(email))
                .filter(user -> Boolean.TRUE.equals(user.getEnabled()) && user.isEmailPendingVerification())
                .filter(user -> !tokenRepository.existsByUserIdAndCreatedAtAfter(user.getId(), cooldownStart))
                .ifPresent(user -> {
                    issue(user);
                    auditService.record("VERIFICATION_EMAIL_RESENT", user.getUsername(), ipAddress, Map.of());
                });
    }

    /** Deletes old links and the accounts that never verified their email. */
    @Transactional
    public void purgeExpired() {
        OffsetDateTime now = OffsetDateTime.now();
        int accounts = userRepository.deleteUnverifiedCreatedBefore(now.minus(unverifiedRetention));
        int tokens = tokenRepository.deleteFinishedBefore(now.minusDays(1));
        if (accounts > 0 || tokens > 0) {
            log.info("Limpieza de verificación de correo: cuentas sin verificar={} enlaces={}", accounts, tokens);
        }
    }

    static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
