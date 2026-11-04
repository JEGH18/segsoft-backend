package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.AccountUnlockToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.InvalidUnlockTokenException;
import co.icesi.pdgseg.repository.AccountUnlockTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Unlock links for accounts locked by failed logins: one is emailed when the lock starts, to the
 * account's verified email, and it lifts the lock without starting a session.
 */
@Service
public class AccountUnlockService {

    private static final Logger log = LoggerFactory.getLogger(AccountUnlockService.class);

    private final AccountUnlockTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;
    private final AuthMailer mailer;
    private final ApplicationEventPublisher eventPublisher;

    public AccountUnlockService(AccountUnlockTokenRepository tokenRepository,
                                UserRepository userRepository,
                                AuditService auditService,
                                AuthMailer mailer,
                                ApplicationEventPublisher eventPublisher) {
        this.tokenRepository = tokenRepository;
        this.userRepository  = userRepository;
        this.auditService    = auditService;
        this.mailer          = mailer;
        this.eventPublisher  = eventPublisher;
    }

    /**
     * Stores an unlock link valid until {@code user}'s lock ends and has it emailed once the
     * login's transaction commits.
     *
     * @return whether a link was sent: only accounts with a verified email get one
     */
    @Transactional
    public boolean issue(User user, int failedAttempts) {
        if (user.getEmail() == null || user.getEmailVerifiedAt() == null || user.getLockedUntil() == null
                || !mailer.isAvailable()) {
            return false;
        }
        OffsetDateTime now = OffsetDateTime.now();
        tokenRepository.invalidatePending(user.getId(), now);
        String token = OneTimeTokens.newToken();
        tokenRepository.save(new AccountUnlockToken(user, OneTimeTokens.hash(token), user.getLockedUntil()));
        long lockMinutes = Math.max(1, Duration.between(now, user.getLockedUntil()).toMinutes());
        eventPublisher.publishEvent(
                new AccountUnlockRequested(user.getUsername(), user.getEmail(), token, failedAttempts, lockMinutes));
        return true;
    }

    /** Consumes the link and lifts the lock; the user still has to log in with the password. */
    @Transactional
    public void unlock(String token, String ipAddress) {
        AccountUnlockToken stored = tokenRepository.findByTokenHash(OneTimeTokens.hash(token))
                .orElseThrow(InvalidUnlockTokenException::new);
        OffsetDateTime now = OffsetDateTime.now();
        if (!stored.isUsable(now)) {
            throw new InvalidUnlockTokenException();
        }
        User user = stored.getUser();
        stored.setUsedAt(now);
        user.setLockedUntil(null);
        user.setFailedAttempts(0);
        user.setLastFailedAt(null);
        tokenRepository.save(stored);
        userRepository.save(user);
        auditService.record("ACCOUNT_UNLOCKED", user.getUsername(), ipAddress, Map.of("via", "email"));
    }

    /** Deletes the links that expired or were used more than a day ago. */
    @Transactional
    public void purgeExpired() {
        int tokens = tokenRepository.deleteFinishedBefore(OffsetDateTime.now().minusDays(1));
        if (tokens > 0) {
            log.info("Limpieza de enlaces de desbloqueo: enlaces={}", tokens);
        }
    }
}
