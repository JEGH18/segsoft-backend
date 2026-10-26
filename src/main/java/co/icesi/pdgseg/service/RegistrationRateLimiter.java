package co.icesi.pdgseg.service;

import co.icesi.pdgseg.exception.TooManyRequestsException;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limits self-registration: every attempt counts against the caller's IP (it hashes a password,
 * which is expensive, and reveals whether a username exists), and every created account counts
 * against a global hourly cap.
 *
 * <p>The client IP comes from X-Forwarded-For, which a caller can forge, so the per-IP limit only
 * slows down casual abuse; the global cap is the hard limit on account creation.
 */
@Component
public class RegistrationRateLimiter {

    private static final int MAX_TRACKED_IPS = 10_000;

    private final int maxPerIpPerHour;
    private final Bucket globalBucket;
    private final Map<String, Bucket> ipBuckets = new ConcurrentHashMap<>();

    public RegistrationRateLimiter(@Value("${auth.registration.max-per-ip-per-hour:20}") int maxPerIpPerHour,
                                   @Value("${auth.registration.max-per-hour:100}") int maxPerHour) {
        this.maxPerIpPerHour = maxPerIpPerHour;
        this.globalBucket = hourly(maxPerHour);
    }

    /** Counts a registration attempt from {@code ipAddress}. */
    public void checkAttempt(String ipAddress) {
        if (ipBuckets.size() > MAX_TRACKED_IPS) {
            ipBuckets.clear();
        }
        Bucket bucket = ipBuckets.computeIfAbsent(String.valueOf(ipAddress), ip -> hourly(maxPerIpPerHour));
        if (!bucket.tryConsume(1)) {
            throw new TooManyRequestsException(
                    "Demasiados intentos de registro desde esta conexión. Intenta de nuevo más tarde.");
        }
    }

    /** Counts an account about to be created. */
    public void checkCreation() {
        if (!globalBucket.tryConsume(1)) {
            throw new TooManyRequestsException(
                    "Se alcanzó el límite de cuentas nuevas por hora. Intenta de nuevo más tarde.");
        }
    }

    private static Bucket hourly(int capacity) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(capacity, Refill.greedy(capacity, Duration.ofHours(1))))
                .build();
    }
}
