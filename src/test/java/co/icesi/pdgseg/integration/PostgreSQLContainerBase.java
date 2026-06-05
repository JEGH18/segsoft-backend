package co.icesi.pdgseg.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Assumptions;
import org.testcontainers.DockerClientFactory;
import org.springframework.test.context.ActiveProfiles;

/**
 * Base class for integration tests.
 * The PostgreSQL 15 container is managed automatically by Testcontainers via the
 * JDBC URL in application-test.yml (jdbc:tc:postgresql:15:///...).
 * No manual container lifecycle management is needed here.
 */
@ActiveProfiles("test")
public abstract class PostgreSQLContainerBase {

    @BeforeAll
    static void requireDockerForIntegrationTests() {
        boolean dockerAvailable;
        try {
            dockerAvailable = DockerClientFactory.instance().isDockerAvailable();
        } catch (Throwable ignored) {
            dockerAvailable = false;
        }
        Assumptions.assumeTrue(
                dockerAvailable,
                "Docker no disponible: se omiten integration tests basados en Testcontainers"
        );
    }
}
