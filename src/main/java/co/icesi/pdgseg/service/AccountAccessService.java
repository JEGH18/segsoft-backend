package co.icesi.pdgseg.service;

import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * An access token is valid for 15 minutes and is not stored anywhere, so on its own it would keep
 * working after its account is locked, disabled or deleted. This check, run on every request that
 * carries one, makes those changes take effect on the next request.
 */
@Service
public class AccountAccessService {

    static final String SESSION_REVOKED = "Tu sesión ya no es válida. Inicia sesión de nuevo.";
    static final String PASSWORD_CHANGED = "La contraseña de tu cuenta cambió, así que cerramos esta sesión. "
            + "Inicia sesión con la contraseña nueva.";

    private final UserRepository userRepository;

    public AccountAccessService(UserRepository userRepository) {
        this.userRepository = userRepository;
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
}
