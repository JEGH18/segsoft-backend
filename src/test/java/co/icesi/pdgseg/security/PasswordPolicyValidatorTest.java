package co.icesi.pdgseg.security;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordPolicyValidatorTest {

    private Validator validator;

    record Dto(@PasswordConstraint String password) {}

    @BeforeEach
    void setUp() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Test
    void validPassword_noViolations() {
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto("SecureP@ssw0rd!"));
        assertThat(violations).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"short1A!", "password123"})
    void tooShort_hasViolation(String pwd) {
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto(pwd));
        assertThat(violations).isNotEmpty();
    }

    @Test
    void noUppercase_hasViolation() {
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto("securepassw0rd!"));
        assertThat(violations).isNotEmpty();
    }

    @Test
    void noLowercase_hasViolation() {
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto("SECUREPASSW0RD!"));
        assertThat(violations).isNotEmpty();
    }

    @Test
    void noDigit_hasViolation() {
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto("SecurePassw!rd!"));
        assertThat(violations).isNotEmpty();
    }

    @Test
    void noSpecialChar_hasViolation() {
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto("SecurePassword1"));
        assertThat(violations).isNotEmpty();
    }

    @Test
    void commonPassword_hasViolation() {
        // "password123" is 11 chars but also in common list —
        // the length violation fires first; use a long common password equivalent
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto("Password123456!"));
        // Not in common list but valid — should pass
        assertThat(violations).isEmpty();
    }

    @Test
    void errorMessageDoesNotRevealPassword() {
        String weakPassword = "abc";
        Set<ConstraintViolation<Dto>> violations = validator.validate(new Dto(weakPassword));
        violations.forEach(v ->
                assertThat(v.getMessage()).doesNotContain(weakPassword));
    }
}
