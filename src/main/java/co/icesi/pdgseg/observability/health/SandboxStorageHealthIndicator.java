package co.icesi.pdgseg.observability.health;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

/**
 * Readiness of the sandbox storage, where uploaded and cloned repositories are extracted and
 * the engine reads them from: writes a temporary file, reads it back and deletes it. Component
 * "sandbox" in /actuator/health/readiness. The path is never in the response.
 */
@Component("sandbox")
public class SandboxStorageHealthIndicator implements HealthIndicator {

    private final Path root;

    public SandboxStorageHealthIndicator(@Value("${sandbox.root}") String root) {
        this.root = Paths.get(root);
    }

    @Override
    public Health health() {
        long started = System.nanoTime();
        Path probe = null;
        try {
            Files.createDirectories(root);
            probe = Files.createTempFile(root, ".health-", ".tmp");
            String written = UUID.randomUUID().toString();
            Files.writeString(probe, written, StandardCharsets.UTF_8);
            String read = Files.readString(probe, StandardCharsets.UTF_8);
            if (!written.equals(read)) {
                return Health.down().withDetail("error", "El archivo de prueba no se leyó igual a como se escribió").build();
            }
            return Health.up().withDetail("responseTimeMs", PostgresHealthIndicator.elapsedMs(started)).build();
        } catch (IOException | RuntimeException ex) {
            return Health.down().withDetail("error", ex.getClass().getSimpleName()).build();
        } finally {
            if (probe != null) {
                try {
                    Files.deleteIfExists(probe);
                } catch (IOException ignored) {
                    // A leftover probe file is harmless; the next check writes a new one.
                }
            }
        }
    }
}
