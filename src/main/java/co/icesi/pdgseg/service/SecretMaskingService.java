package co.icesi.pdgseg.service;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Second line of defense behind the engine's SecretMasker: evidence snippets
 * should already arrive masked, but anything that slipped through is masked
 * again here before it leaves the backend (API responses, exported reports).
 * Masking is idempotent -- an already masked value is left as is.
 */
@Service
public class SecretMaskingService {

    public static final String MASK = "*****";

    /**
     * key=value / key: "value" assignments whose key names a credential. The
     * optional quote after the key covers JSON/YAML ("api_key": "...").
     */
    private static final Pattern KEY_VALUE_PATTERN = Pattern.compile(
            "(?i)((?:api[_-]?key|access[_-]?key|private[_-]?key|secret|token|password|passwd|pwd|credentials?)"
                    + "[\"']?\\s*[:=]\\s*[\"']?)([^\\s\"']+)");

    /** The mask plus trailing punctuation only, so "*****secret" is still masked. */
    private static final Pattern ALREADY_MASKED = Pattern.compile("\\*{5}[,;)\\]}]*");

    /** Secrets recognizable by their shape even without a telling key name. */
    private static final List<Pattern> VALUE_PATTERNS = List.of(
            // AWS access key id
            Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"),
            // GitHub personal/OAuth/app tokens
            Pattern.compile("\\bgh[pousr]_[A-Za-z0-9]{36,}\\b"),
            // Slack tokens
            Pattern.compile("\\bxox[abprs]-[A-Za-z0-9-]{10,}"),
            // Stripe-style live/test keys
            Pattern.compile("\\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\\b"),
            // Google API key
            Pattern.compile("\\bAIza[0-9A-Za-z_\\-]{35}"),
            // JSON Web Token
            Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}")
    );

    private static final Pattern BEARER_PATTERN = Pattern.compile("(?i)(bearer\\s+)[A-Za-z0-9\\-._~+/]{16,}=*");

    /** user:password@ embedded in a URL (e.g. JDBC or git remotes). */
    private static final Pattern URL_CREDENTIALS_PATTERN = Pattern.compile("(://[^/\\s:@]+:)[^@\\s/]+(@)");

    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN ([A-Z ]*)PRIVATE KEY-----.*?(?:-----END \\1PRIVATE KEY-----|\\z)", Pattern.DOTALL);

    public String mask(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String masked = PRIVATE_KEY_PATTERN.matcher(value)
                .replaceAll(match -> Matcher.quoteReplacement(
                        "-----BEGIN " + match.group(1) + "PRIVATE KEY-----" + MASK
                                + "-----END " + match.group(1) + "PRIVATE KEY-----"));
        // A value already starting with the mask was masked upstream (the
        // engine masks up to the next ',' or ';'); re-masking it would also eat
        // the punctuation that follows it.
        masked = KEY_VALUE_PATTERN.matcher(masked).replaceAll(match ->
                ALREADY_MASKED.matcher(match.group(2)).matches() ? Matcher.quoteReplacement(match.group())
                        : Matcher.quoteReplacement(match.group(1) + MASK));
        masked = BEARER_PATTERN.matcher(masked).replaceAll("$1" + Matcher.quoteReplacement(MASK));
        masked = URL_CREDENTIALS_PATTERN.matcher(masked).replaceAll("$1" + Matcher.quoteReplacement(MASK) + "$2");
        for (Pattern pattern : VALUE_PATTERNS) {
            masked = pattern.matcher(masked).replaceAll(Matcher.quoteReplacement(MASK));
        }
        return masked;
    }
}
