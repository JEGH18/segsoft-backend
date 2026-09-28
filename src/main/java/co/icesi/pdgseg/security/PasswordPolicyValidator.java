package co.icesi.pdgseg.security;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.core.io.ClassPathResource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public class PasswordPolicyValidator implements ConstraintValidator<PasswordConstraint, String> {

    private static final int MIN_LENGTH = 12;
    private static final Pattern HAS_UPPER   = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWER   = Pattern.compile("[a-z]");
    private static final Pattern HAS_DIGIT   = Pattern.compile("[0-9]");
    private static final Pattern HAS_SPECIAL = Pattern.compile("[^A-Za-z0-9]");

    private static final Set<String> COMMON_PASSWORDS = loadCommonPasswords();

    private static Set<String> loadCommonPasswords() {
        Set<String> passwords = new HashSet<>();
        try {
            ClassPathResource resource = new ClassPathResource("common-passwords.txt");
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) {
                        passwords.add(trimmed.toLowerCase());
                    }
                }
            }
        } catch (Exception e) {
            // If resource not found, log and continue without common password check
        }
        return passwords;
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isBlank()) {
            addViolation(context, "La contraseña no puede estar vacía");
            return false;
        }
        if (password.length() < MIN_LENGTH) {
            addViolation(context, "La contraseña debe tener al menos " + MIN_LENGTH + " caracteres");
            return false;
        }
        if (!HAS_UPPER.matcher(password).find()) {
            addViolation(context, "La contraseña debe contener al menos una letra mayúscula");
            return false;
        }
        if (!HAS_LOWER.matcher(password).find()) {
            addViolation(context, "La contraseña debe contener al menos una letra minúscula");
            return false;
        }
        if (!HAS_DIGIT.matcher(password).find()) {
            addViolation(context, "La contraseña debe contener al menos un dígito");
            return false;
        }
        if (!HAS_SPECIAL.matcher(password).find()) {
            addViolation(context, "La contraseña debe contener al menos un carácter especial");
            return false;
        }
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            addViolation(context, "La contraseña elegida es demasiado común");
            return false;
        }
        return true;
    }

    private void addViolation(ConstraintValidatorContext context, String message) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    }
}
