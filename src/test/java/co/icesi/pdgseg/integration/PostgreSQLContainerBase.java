package co.icesi.pdgseg.integration;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.test.context.ActiveProfiles;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Base class for integration tests.
 *
 * <p>The tests run against a real PostgreSQL 15 configured in application-test.yml
 * (jdbc:postgresql://localhost:5432/pdgseg_test). CI pipelines point them to their own
 * database with SPRING_DATASOURCE_URL / SPRING_DATASOURCE_USERNAME / SPRING_DATASOURCE_PASSWORD.
 *
 * <p>Without a reachable database the tests are skipped locally, but they fail when
 * {@code CI=true}: a pipeline must never report a green build that ran no integration test.
 * The check is an {@link ExecutionCondition} so it runs before Spring loads the context.
 */
@ActiveProfiles("test")
@ExtendWith(PostgreSQLContainerBase.RequireTestDatabase.class)
public abstract class PostgreSQLContainerBase {

    static class RequireTestDatabase implements ExecutionCondition {

        // Same defaults as src/main/resources/application-test.yml.
        private static final String DEFAULT_URL = "jdbc:postgresql://localhost:5432/pdgseg_test";
        private static final String DEFAULT_CREDENTIAL = "pdgseg_test";

        // Checked once per JVM: null = reachable, otherwise why it is not.
        private static String unavailableReason;
        private static boolean checked;

        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
            String reason = unavailableReason();
            if (reason == null) {
                return ConditionEvaluationResult.enabled("Base de datos de integración disponible");
            }
            if ("true".equalsIgnoreCase(System.getenv("CI"))) {
                throw new IllegalStateException(reason);
            }
            return ConditionEvaluationResult.disabled(reason + " (se omiten los integration tests)");
        }

        private static synchronized String unavailableReason() {
            if (!checked) {
                String url = setting("SPRING_DATASOURCE_URL", DEFAULT_URL);
                try (Connection ignored = DriverManager.getConnection(url,
                        setting("SPRING_DATASOURCE_USERNAME", DEFAULT_CREDENTIAL),
                        setting("SPRING_DATASOURCE_PASSWORD", DEFAULT_CREDENTIAL))) {
                    unavailableReason = null;
                } catch (SQLException e) {
                    unavailableReason = "Base de datos de integración no disponible en " + url + ": " + e.getMessage();
                }
                checked = true;
            }
            return unavailableReason;
        }

        private static String setting(String name, String defaultValue) {
            String value = System.getenv(name);
            return value == null || value.isBlank() ? defaultValue : value;
        }
    }
}
