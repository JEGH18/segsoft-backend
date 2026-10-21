package co.icesi.pdgseg.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Creates the login accounts of a deployment from {@code SEGSOFT_ACCOUNTS}, so no password lives in
 * the repositories.
 *
 * <p>Format: one {@code usuario:ROL:contraseña} entry per line or separated by {@code ;}. The
 * password may contain {@code :} but not {@code ;}. Example:
 * {@code admin:SECURITY_ADMIN:…;auditor:AUDITOR:…;dev:DEVELOPER:…}.
 *
 * <p>The application refuses to start if the variable is missing or invalid: migration V3 seeds
 * {@code admin/admin123}, and the dev profile publishes the passwords of the demo accounts. Demo
 * accounts not listed in the variable are disabled while they still have their public password.
 */
@Component
@Profile("prod")
public class ProdAccountsInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(ProdAccountsInitializer.class);

    static final int MIN_PASSWORD_LENGTH = 12;
    static final Set<String> ROLES = Set.of("DEVELOPER", "AUDITOR", "SECURITY_ADMIN");
    /** Accounts whose passwords are published in the repositories (migration V3 and DevDataInitializer). */
    static final Map<String, String> PUBLIC_DEMO_PASSWORDS = Map.of(
            "admin", "admin123",
            "auditor", "auditor123",
            "dev", "dev123",
            "usuario", "usuario123");
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9._-]{3,100}");

    record Account(String username, String role, String password) {
        @Override
        public String toString() {
            return username + " (" + role + ")";
        }
    }

    private final AccountSeeder accountSeeder;
    private final String accountsSpec;

    public ProdAccountsInitializer(AccountSeeder accountSeeder, @Value("${segsoft.accounts:}") String accountsSpec) {
        this.accountSeeder = accountSeeder;
        this.accountsSpec = accountsSpec;
    }

    @Override
    public void run(String... args) {
        List<Account> accounts = parse(accountsSpec);
        Set<String> configured = new HashSet<>();
        for (Account account : accounts) {
            accountSeeder.replace(account.username(), account.password(), account.role());
            configured.add(account.username());
        }
        PUBLIC_DEMO_PASSWORDS.forEach((username, publicPassword) -> {
            if (!configured.contains(username) && accountSeeder.hasPassword(username, publicPassword)) {
                accountSeeder.disable(username);
                log.warn("Cuenta de demostración deshabilitada porque su contraseña es pública: {}", username);
            }
        });
        log.info("Cuentas de producción listas: {}", accounts);
    }

    static List<Account> parse(String spec) {
        List<Account> accounts = new ArrayList<>();
        Set<String> usernames = new HashSet<>();
        int position = 0;
        for (String entry : spec == null ? new String[0] : spec.split("[;\\r\\n]+")) {
            if (entry.isBlank()) {
                continue;
            }
            position++;
            String[] parts = entry.trim().split(":", 3);
            if (parts.length != 3) {
                throw invalid("la entrada " + position + " no tiene el formato usuario:ROL:contraseña.");
            }
            String username = parts[0].trim();
            String role = parts[1].trim();
            String password = parts[2];
            if (!USERNAME.matcher(username).matches()) {
                throw invalid("el usuario de la entrada " + position
                        + " debe tener entre 3 y 100 letras, dígitos, '.', '_' o '-'.");
            }
            if (!ROLES.contains(role)) {
                throw invalid("el rol de " + username + " debe ser uno de " + ROLES + ".");
            }
            // Also rules out the public demo passwords, all shorter than this.
            if (password.length() < MIN_PASSWORD_LENGTH) {
                throw invalid("la contraseña de " + username + " debe tener al menos "
                        + MIN_PASSWORD_LENGTH + " caracteres.");
            }
            if (!usernames.add(username)) {
                throw invalid("el usuario " + username + " aparece más de una vez.");
            }
            accounts.add(new Account(username, role, password));
        }
        if (accounts.isEmpty()) {
            throw invalid("no está definida. El perfil prod necesita las cuentas de acceso "
                    + "(usuario:ROL:contraseña, separadas por ';').");
        }
        if (accounts.stream().noneMatch(account -> account.role().equals("SECURITY_ADMIN"))) {
            throw invalid("debe haber al menos una cuenta SECURITY_ADMIN.");
        }
        return accounts;
    }

    private static IllegalStateException invalid(String detail) {
        return new IllegalStateException("SEGSOFT_ACCOUNTS inválida: " + detail);
    }
}
