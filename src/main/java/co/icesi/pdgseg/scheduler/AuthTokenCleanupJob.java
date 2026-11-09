package co.icesi.pdgseg.scheduler;

import co.icesi.pdgseg.service.AccountUnlockService;
import co.icesi.pdgseg.service.EmailVerificationService;
import co.icesi.pdgseg.service.PasswordResetService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Deletes old verification and unlock links, and the accounts that never verified their email. */
@Component
public class AuthTokenCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenCleanupJob.class);

    private final EmailVerificationService emailVerificationService;
    private final AccountUnlockService accountUnlockService;
    private final PasswordResetService passwordResetService;

    public AuthTokenCleanupJob(EmailVerificationService emailVerificationService,
                               AccountUnlockService accountUnlockService,
                               PasswordResetService passwordResetService) {
        this.emailVerificationService = emailVerificationService;
        this.accountUnlockService = accountUnlockService;
        this.passwordResetService = passwordResetService;
    }

    // Runs every day at 03:30
    @Scheduled(cron = "0 30 3 * * *")
    public void purgeExpired() {
        try {
            emailVerificationService.purgeExpired();
        } catch (Exception e) {
            log.error("Error durante la limpieza de cuentas sin verificar", e);
        }
        try {
            accountUnlockService.purgeExpired();
        } catch (Exception e) {
            log.error("Error durante la limpieza de enlaces de desbloqueo", e);
        }
        try {
            passwordResetService.purgeExpired();
        } catch (Exception e) {
            log.error("Error durante la limpieza de enlaces de cambio de contraseña", e);
        }
    }
}
