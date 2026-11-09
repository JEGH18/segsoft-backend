package co.icesi.pdgseg.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Format of the CI/CD API tokens: "pdgseg_" followed by 32 random bytes in URL-safe Base64.
 * The prefix tells them apart from a session JWT in the same Authorization header.
 * Only {@link #hash} of a token is ever stored.
 */
public final class ApiTokens {

    public static final String PREFIX = "pdgseg_";
    /** Characters kept in clear to recognize a token in a list: the prefix and 5 random ones. */
    public static final int DISPLAY_PREFIX_LENGTH = PREFIX.length() + 5;

    private static final int RANDOM_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private ApiTokens() {}

    public static boolean looksLikeApiToken(String bearer) {
        return bearer != null && bearer.startsWith(PREFIX);
    }

    public static String generate() {
        byte[] bytes = new byte[RANDOM_BYTES];
        RANDOM.nextBytes(bytes);
        return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String displayPrefix(String plaintext) {
        return plaintext.substring(0, Math.min(DISPLAY_PREFIX_LENGTH, plaintext.length()));
    }

    /** Hex SHA-256. A fast hash is enough: the token has 256 random bits, nothing to brute-force. */
    public static String hash(String plaintext) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(plaintext.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }
}
