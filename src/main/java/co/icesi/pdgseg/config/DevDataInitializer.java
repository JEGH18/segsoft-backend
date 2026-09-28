package co.icesi.pdgseg.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds test users on startup when running with the default (dev) profile.
 * Users: admin/admin123 (SECURITY_ADMIN), auditor/auditor123 (AUDITOR), dev/dev123 (DEVELOPER)
 */
@Component
@Profile("!prod")
public class DevDataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DevDataInitializer.class);

    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwordEncoder;

    public DevDataInitializer(JdbcTemplate jdbc, PasswordEncoder passwordEncoder) {
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        upsertUser("admin",   "admin123",   "SECURITY_ADMIN");
        upsertUser("auditor", "auditor123", "AUDITOR");
        upsertUser("dev",     "dev123",     "DEVELOPER");
        upsertUser("usuario", "usuario123", "DEVELOPER");
    }

    private void upsertUser(String username, String rawPassword, String roleName) {
        String hash = passwordEncoder.encode(rawPassword);

        int updated = jdbc.update(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                hash, username
        );

        if (updated == 0) {
            jdbc.update(
                    "INSERT INTO users (username, password_hash, enabled) VALUES (?, ?, true) ON CONFLICT (username) DO NOTHING",
                    username, hash
            );
        }

        jdbc.update("""
                INSERT INTO user_roles (user_id, role_id)
                SELECT u.id, r.id
                FROM users u, roles r
                WHERE u.username = ? AND r.name = ?
                ON CONFLICT DO NOTHING
                """,
                username, roleName
        );

        log.info("Dev user ready: {} (role={})", username, roleName);
    }
}
