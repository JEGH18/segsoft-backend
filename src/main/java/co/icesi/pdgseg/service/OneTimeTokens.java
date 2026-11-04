package co.icesi.pdgseg.service;

import java.security.SecureRandom;
import java.util.Base64;

/** Random tokens for the links sent by email (verification, unlock). Only their hash is stored. */
final class OneTimeTokens {

    private static final int TOKEN_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private OneTimeTokens() {}

    /** 32 random bytes in URL-safe Base64, without padding (43 characters). */
    static String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String hash(String token) {
        return ReportChecksum.sha256Hex(token.trim());
    }
}
