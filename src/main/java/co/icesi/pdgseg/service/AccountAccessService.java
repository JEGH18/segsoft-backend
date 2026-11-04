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

    private final UserRepository userRepository;

    public AccountAccessService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * @throws AccountLockedException if the account is locked by failed logins
     * @throws AuthException          if the account was disabled or deleted
     */
    @Transactional(readOnly = true)
    public void requireUsable(String username) {
        UserRepository.AccessState state = userRepository.findAccessStateByUsername(username)
                .orElseThrow(() -> new AuthException(SESSION_REVOKED));
        if (!Boolean.TRUE.equals(state.getEnabled())) {
            throw new AuthException(SESSION_REVOKED);
        }
        if (AuthService.isLocked(state.getLockedUntil())) {
            throw AuthService.stillLocked(state.getLockedUntil(),
                    AuthService.hasVerifiedEmail(state.getEmail(), state.getEmailVerifiedAt()));
        }
    }
}
