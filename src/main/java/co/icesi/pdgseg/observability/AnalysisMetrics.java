package co.icesi.pdgseg.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Analysis metrics, served in /actuator/prometheus as:
 * <ul>
 *   <li>{@code analyses_executed_total{status}}: analyses that finished, by final status
 *       (COMPLETED, FAILED, CANCELLED).</li>
 *   <li>{@code analyses_running_current}: analyses running right now on this backend.</li>
 *   <li>{@code rule_execution_duration_seconds{ruleType,outcome}}: histogram of each request
 *       that runs a rule in the engine (one batch of files), to spot slow rules or a slow engine.</li>
 *   <li>{@code rule_execution_errors_total{ruleType,errorCode}}: rule execution errors, whether
 *       the engine reported them or it could not be reached (ENGINE_ERROR).</li>
 * </ul>
 * Tags only take values from small fixed sets (rule types, error codes), never ids.
 */
@Component
public class AnalysisMetrics {

    private final MeterRegistry registry;
    private final AtomicInteger running = new AtomicInteger();

    public AnalysisMetrics(MeterRegistry registry) {
        this.registry = registry;
        Gauge.builder("analyses.running.current", running, AtomicInteger::get)
                .description("Análisis en ejecución en este momento")
                .register(registry);
        // Registered up front so the series exist (at 0) before the first analysis ends.
        for (String status : List.of("COMPLETED", "FAILED", "CANCELLED")) {
            executedCounter(status);
        }
    }

    public void analysisStarted() {
        running.incrementAndGet();
    }

    /** Pairs with {@link #analysisStarted()}; {@code status} is the analysis' final status. */
    public void analysisFinished(String status) {
        running.decrementAndGet();
        executedCounter(status).increment();
    }

    public void ruleExecuted(String ruleType, boolean succeeded, Duration duration) {
        Timer.builder("rule.execution.duration")
                .description("Duración de cada ejecución de una regla en el motor (un lote de archivos)")
                .tag("ruleType", tagValue(ruleType))
                .tag("outcome", succeeded ? "success" : "error")
                .publishPercentileHistogram()
                .register(registry)
                .record(duration);
    }

    public void ruleError(String ruleType, String errorCode) {
        Counter.builder("rule.execution.errors")
                .description("Errores de ejecución de reglas, por tipo de regla y código de error")
                .tag("ruleType", tagValue(ruleType))
                .tag("errorCode", tagValue(errorCode))
                .register(registry)
                .increment();
    }

    private Counter executedCounter(String status) {
        return Counter.builder("analyses.executed")
                .description("Análisis terminados, por estado final")
                .tag("status", status)
                .register(registry);
    }

    private static String tagValue(String value) {
        return value != null && !value.isBlank() ? value : "UNKNOWN";
    }
}
