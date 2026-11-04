package co.icesi.pdgseg.scheduler;

import co.icesi.pdgseg.service.EmailVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class EmailVerificationCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(EmailVerificationCleanupJob.class);

    private final EmailVerificationService emailVerificationService;

    public EmailVerificationCleanupJob(EmailVerificationService emailVerificationService) {
        this.emailVerificationService = emailVerificationService;
    }

    // Runs every day at 03:30
    @Scheduled(cron = "0 30 3 * * *")
    public void purgeUnverifiedAccounts() {
        try {
            emailVerificationService.purgeExpired();
        } catch (Exception e) {
            log.error("Error durante la limpieza de cuentas sin verificar", e);
        }
    }
}
