package co.icesi.pdgseg.service;

import co.icesi.pdgseg.exception.TooManyRequestsException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegistrationRateLimiterTest {

    @Test
    void checkAttempt_limitsEachIpSeparately() {
        RegistrationRateLimiter limiter = new RegistrationRateLimiter(2, 100);

        limiter.checkAttempt("10.0.0.1");
        limiter.checkAttempt("10.0.0.1");
        assertThatThrownBy(() -> limiter.checkAttempt("10.0.0.1"))
                .isInstanceOf(TooManyRequestsException.class)
                .hasMessageContaining("esta conexión");
        assertThatCode(() -> limiter.checkAttempt("10.0.0.2")).doesNotThrowAnyException();
    }

    @Test
    void checkCreation_capsAccountsAcrossAllIps() {
        RegistrationRateLimiter limiter = new RegistrationRateLimiter(100, 2);

        limiter.checkCreation();
        limiter.checkCreation();
        assertThatThrownBy(limiter::checkCreation)
                .isInstanceOf(TooManyRequestsException.class)
                .hasMessageContaining("por hora");
    }

    @Test
    void checkAttempt_acceptsAMissingIp() {
        assertThatCode(() -> new RegistrationRateLimiter(1, 1).checkAttempt(null)).doesNotThrowAnyException();
    }
}
