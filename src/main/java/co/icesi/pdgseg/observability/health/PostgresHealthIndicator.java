package co.icesi.pdgseg.observability.health;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Readiness of PostgreSQL: an active connection that answers {@code SELECT 1}. Replaces Spring
 * Boot's "db" indicator (management.health.db.enabled=false). Component "postgres" in
 * /actuator/health/readiness.
 */
@Component("postgres")
public class PostgresHealthIndicator implements HealthIndicator {

    private final JdbcTemplate jdbcTemplate;

    public PostgresHealthIndicator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public Health health() {
        long started = System.nanoTime();
        try {
            Integer one = jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            if (one == null || one != 1) {
                return Health.down().withDetail("error", "SELECT 1 devolvió " + one).build();
            }
            return Health.up().withDetail("responseTimeMs", elapsedMs(started)).build();
        } catch (RuntimeException ex) {
            // Only the exception type: its message may name the host or the user of the database.
            return Health.down().withDetail("error", ex.getClass().getSimpleName()).build();
        }
    }

    static long elapsedMs(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000;
    }
}
