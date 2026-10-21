package co.icesi.pdgseg.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Seeds test users on startup when running with the default (dev) profile.
 * Users: admin/admin123 (SECURITY_ADMIN), auditor/auditor123 (AUDITOR), dev/dev123 (DEVELOPER)
 */
@Component
@Profile("!prod")
public class DevDataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DevDataInitializer.class);

    private final AccountSeeder accountSeeder;

    public DevDataInitializer(AccountSeeder accountSeeder) {
        this.accountSeeder = accountSeeder;
    }

    @Override
    public void run(String... args) {
        upsertUser("admin",   "admin123",   "SECURITY_ADMIN");
        upsertUser("auditor", "auditor123", "AUDITOR");
        upsertUser("dev",     "dev123",     "DEVELOPER");
        upsertUser("usuario", "usuario123", "DEVELOPER");
    }

    private void upsertUser(String username, String rawPassword, String roleName) {
        accountSeeder.upsert(username, rawPassword, roleName);
        log.info("Dev user ready: {} (role={})", username, roleName);
    }
}
