package co.icesi.pdgseg.export;

import co.icesi.pdgseg.service.SecretMaskingService;
import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Cleans every user- or repository-controlled string before an exporter
 * embeds it. Exported reports end up in front of people outside the tool, so
 * this is shared by all exporters rather than left to each one.
 */
@Component
public class ReportTextSanitizer {

    public static final int MAX_SNIPPET_LENGTH = 600;
    public static final int MAX_FIELD_LENGTH = 400;

    /**
     * C0/C1 control characters (except tab and newline), bidi overrides and
     * isolates (the "Trojan Source" trick, which can make displayed text differ
     * from its real content), zero-width characters and the BOM.
     */
    private static final Pattern UNSAFE_CHARS = Pattern.compile(
            "[\\x00-\\x08\\x0B-\\x1F\\x7F-\\x9F\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\uFEFF]");

    private final SecretMaskingService secretMaskingService;

    public ReportTextSanitizer(SecretMaskingService secretMaskingService) {
        this.secretMaskingService = secretMaskingService;
    }

    /** Sanitizes a short, single-line field (names, paths, ids, URLs). */
    public String field(String value) {
        return clean(value, MAX_FIELD_LENGTH, true);
    }

    /** Sanitizes free text that may span lines (suggested actions). */
    public String text(String value) {
        return clean(value, MAX_FIELD_LENGTH * 2, false);
    }

    /** Sanitizes an evidence snippet, which is allowed to be longer than a field. */
    public String snippet(String value) {
        return clean(value, MAX_SNIPPET_LENGTH, false);
    }

    /**
     * Every value is masked, not only snippets: they should already arrive
     * masked from the engine, but a secret that slipped past it -- or one
     * sitting in a git URL, a path or a suggested action -- must not reach the
     * exported file either. Masking runs after invisible characters are
     * stripped, so a zero-width space inside "password" cannot dodge the patterns, and before
     * truncation, so a cut can never split a secret out of its key.
     */
    private String clean(String value, int maxLength, boolean singleLine) {
        if (value == null) {
            return "";
        }
        String cleaned = Normalizer.normalize(value, Normalizer.Form.NFC)
                .replace("\r\n", "\n")
                .replace('\r', '\n');
        cleaned = UNSAFE_CHARS.matcher(cleaned).replaceAll("");
        cleaned = cleaned.replace("\t", "    ");
        if (singleLine) {
            cleaned = cleaned.replace('\n', ' ');
        }
        cleaned = secretMaskingService.mask(cleaned).strip();
        if (cleaned.length() > maxLength) {
            int end = Character.isHighSurrogate(cleaned.charAt(maxLength - 1)) ? maxLength - 1 : maxLength;
            cleaned = cleaned.substring(0, end) + " […]";
        }
        return cleaned;
    }
}
