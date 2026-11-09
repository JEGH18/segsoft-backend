package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.ApiToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.repository.ApiTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import co.icesi.pdgseg.security.ApiTokens;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;

/**
 * Decides whether a credential sent with a request may still be used.
 *
 * <p>An access token is valid for 15 minutes and is not stored anywhere, so on its own it would keep
 * working after its account is locked, disabled or deleted. {@link #requireUsable}, run on every
 * request that carries one, makes those changes take effect on the next request.
 *
 * <p>A CI/CD API token is looked up by its hash on every request ({@link #authenticateApiToken}), and
 * goes through the same account checks.
 */
@Service
public class AccountAccessService {

    static final String SESSION_REVOKED = "Tu sesión ya no es válida. Inicia sesión de nuevo.";
    static final String PASSWORD_CHANGED = "La contraseña de tu cuenta cambió, así que cerramos esta sesión. "
            + "Inicia sesión con la contraseña nueva.";
    static final String API_TOKEN_INVALID = "El token de API no es válido, venció o fue revocado.";
    static final String API_TOKEN_ACCOUNT_DISABLED = "La cuenta dueña de este token de API está deshabilitada.";

    /** last_used_at is written at most this often per token, not on every request of a pipeline. */
    static final Duration LAST_USED_RESOLUTION = Duration.ofMinutes(1);

    /** Who an API token authenticates as. */
    public record ApiTokenIdentity(String username, List<String> roles) {}

    private final UserRepository userRepository;
    private final ApiTokenRepository apiTokenRepository;
    private final Clock clock;

    @Autowired
    public AccountAccessService(UserRepository userRepository, ApiTokenRepository apiTokenRepository) {
        this(userRepository, apiTokenRepository, Clock.systemUTC());
    }

    AccountAccessService(UserRepository userRepository, ApiTokenRepository apiTokenRepository, Clock clock) {
        this.userRepository = userRepository;
        this.apiTokenRepository = apiTokenRepository;
        this.clock = clock;
    }

    /**
     * @throws AccountLockedException if the account is locked by failed logins
     * @throws AuthException          if the account was disabled or deleted, or its password changed
     *                                after {@code tokenVersion} was issued
     */
    @Transactional(readOnly = true)
    public void requireUsable(String username, int tokenVersion) {
        UserRepository.AccessState state = userRepository.findAccessStateByUsername(username)
                .orElseThrow(() -> new AuthException(SESSION_REVOKED));
        if (!Boolean.TRUE.equals(state.getEnabled())) {
            throw new AuthException(SESSION_REVOKED);
        }
        int current = state.getTokenVersion() == null ? 0 : state.getTokenVersion();
        if (tokenVersion != current) {
            throw new AuthException(PASSWORD_CHANGED);
        }
        if (AuthService.isLocked(state.getLockedUntil())) {
            throw AuthService.stillLocked(state.getLockedUntil(),
                    AuthService.hasVerifiedEmail(state.getEmail(), state.getEmailVerifiedAt()));
        }
    }

    /**
     * Resolves a plaintext API token to the user it belongs to. A password change does not revoke API
     * tokens (they are revoked one by one), but a disabled or locked account cannot use them.
     *
     * @throws AuthException          if the token is unknown, expired or revoked, or its owner is disabled
     * @throws AccountLockedException if its owner is locked by failed logins
     */
    @Transactional
    public ApiTokenIdentity authenticateApiToken(String plaintext) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        ApiToken token = apiTokenRepository.findByTokenHash(ApiTokens.hash(plaintext))
                .filter(t -> !t.isExpired(now))
                .orElseThrow(() -> new AuthException(API_TOKEN_INVALID));

        User owner = token.getCreatedBy();
        if (!Boolean.TRUE.equals(owner.getEnabled())) {
            throw new AuthException(API_TOKEN_ACCOUNT_DISABLED);
        }
        if (AuthService.isLocked(owner.getLockedUntil())) {
            throw AuthService.stillLocked(owner.getLockedUntil(),
                    AuthService.hasVerifiedEmail(owner.getEmail(), owner.getEmailVerifiedAt()));
        }

        if (token.getLastUsedAt() == null || token.getLastUsedAt().isBefore(now.minus(LAST_USED_RESOLUTION))) {
            apiTokenRepository.markUsed(token.getId(), now);
        }

        List<String> roles = owner.getRoles().stream().map(r -> r.getName().name()).sorted().toList();
        return new ApiTokenIdentity(owner.getUsername(), roles);
    }
}
