package co.icesi.pdgseg.observability;

import co.icesi.pdgseg.service.SecretMaskingService;
import com.fasterxml.jackson.core.JsonStreamContext;
import net.logstash.logback.mask.ValueMasker;

/**
 * Masks secrets in every string value of a JSON log line (message, stack trace, MDC fields)
 * before it is written, with the same patterns that mask the evidence of findings: passwords,
 * tokens and keys in key=value form, "Bearer ..." (so an Authorization header never reaches a
 * log), JWTs, SegSoft API tokens, credentials in URLs and private keys. Wired in
 * logback-spring.xml; Logback creates it, not Spring.
 */
public class SecretLogValueMasker implements ValueMasker {

    private final SecretMaskingService masking = new SecretMaskingService();

    @Override
    public Object mask(JsonStreamContext context, Object value) {
        if (!(value instanceof CharSequence text)) {
            return null;
        }
        String original = text.toString();
        String masked = masking.mask(original);
        // null = leave the value as it is.
        return masked.equals(original) ? null : masked;
    }
}
