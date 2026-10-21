package co.icesi.pdgseg.config;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Creates or updates a login account on startup. Shared by the dev and prod initializers.
 */
@Component
public class AccountSeeder {

    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwordEncoder;

    public AccountSeeder(JdbcTemplate jdbc, PasswordEncoder passwordEncoder) {
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
    }

    /** Sets the password of {@code username} (creating the account if needed) and grants it {@code roleName}. */
    public void upsert(String username, String rawPassword, String roleName) {
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
    }

    /**
     * Like {@link #upsert}, but the account ends up enabled, unlocked and with {@code roleName} as its only role.
     */
    public void replace(String username, String rawPassword, String roleName) {
        upsert(username, rawPassword, roleName);
        jdbc.update("""
                DELETE FROM user_roles
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                  AND role_id <> (SELECT id FROM roles WHERE name = ?)
                """,
                username, roleName
        );
        jdbc.update(
                "UPDATE users SET enabled = true, failed_attempts = 0, locked_until = NULL WHERE username = ?",
                username
        );
    }

    /** True when the enabled account {@code username} exists and its password is {@code rawPassword}. */
    public boolean hasPassword(String username, String rawPassword) {
        return jdbc.queryForList(
                        "SELECT password_hash FROM users WHERE username = ? AND enabled = true",
                        String.class, username)
                .stream()
                .anyMatch(hash -> passwordEncoder.matches(rawPassword, hash));
    }

    public void disable(String username) {
        jdbc.update("UPDATE users SET enabled = false WHERE username = ?", username);
    }
}
