package co.icesi.pdgseg.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;

/**
 * SHA-256 of a report's content in canonical JSON form.
 *
 * reports.content is JSONB, which PostgreSQL normalizes (key order,
 * whitespace, number formatting), so the bytes read back differ from the
 * bytes written. The checksum is therefore taken over a canonical
 * serialization of the JSON value -- object keys sorted, no insignificant
 * whitespace, numbers without redundant zeros -- which is the same whether
 * computed from the freshly serialized content or from what JSONB returns.
 *
 * FROZEN FORMAT: every stored checksum depends on this exact canonical form
 * (V32 migration included). Changing it invalidates all existing reports;
 * ReportChecksumTest pins it with a golden value.
 */
public final class ReportChecksum {

    private static final ObjectMapper PARSER = new ObjectMapper()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final ObjectMapper STRINGS = new ObjectMapper();

    private ReportChecksum() {
    }

    /** SHA-256 (lower-case hex) of the canonical form of {@code json}. */
    public static String of(String json) {
        return sha256Hex(canonical(json));
    }

    static String canonical(String json) {
        try {
            StringBuilder out = new StringBuilder(json.length());
            write(PARSER.readTree(json), out);
            return out.toString();
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("El contenido del reporte no es JSON válido", e);
        }
    }

    private static void write(JsonNode node, StringBuilder out) throws JsonProcessingException {
        if (node.isObject()) {
            List<String> names = new ArrayList<>();
            for (Iterator<String> it = node.fieldNames(); it.hasNext(); ) {
                names.add(it.next());
            }
            names.sort(null); // UTF-16 code unit order
            out.append('{');
            for (int i = 0; i < names.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append(STRINGS.writeValueAsString(names.get(i))).append(':');
                write(node.get(names.get(i)), out);
            }
            out.append('}');
        } else if (node.isArray()) {
            out.append('[');
            for (int i = 0; i < node.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(node.get(i), out);
            }
            out.append(']');
        } else if (node.isNumber()) {
            out.append(canonicalNumber(node.decimalValue()));
        } else if (node.isTextual()) {
            out.append(STRINGS.writeValueAsString(node.textValue()));
        } else {
            out.append(node.toString()); // true, false, null
        }
    }

    private static String canonicalNumber(BigDecimal value) {
        if (value.signum() == 0) {
            return "0";
        }
        return value.stripTrailingZeros().toPlainString();
    }

    static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }
}
