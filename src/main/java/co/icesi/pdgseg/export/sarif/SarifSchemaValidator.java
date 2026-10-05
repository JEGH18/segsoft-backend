package co.icesi.pdgseg.export.sarif;

import co.icesi.pdgseg.exception.SarifValidationException;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;

/**
 * Validates SARIF documents against the official OASIS SARIF 2.1.0 schema
 * (errata01), bundled in src/main/resources/sarif so validation never needs
 * network access. The schema is parsed once, at startup.
 */
@Component
public class SarifSchemaValidator {

    static final String SCHEMA_RESOURCE = "/sarif/sarif-schema-2.1.0.json";
    static final int MAX_REPORTED_VIOLATIONS = 50;

    private final Schema schema;

    public SarifSchemaValidator() {
        try (InputStream in = SarifSchemaValidator.class.getResourceAsStream(SCHEMA_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Schema SARIF no encontrado en el classpath: " + SCHEMA_RESOURCE);
            }
            JSONObject rawSchema = new JSONObject(new JSONTokener(in));
            this.schema = SchemaLoader.builder()
                    .schemaJson(rawSchema)
                    .build()
                    .load()
                    .build();
        } catch (IOException e) {
            throw new UncheckedIOException("No se pudo leer el schema SARIF", e);
        }
    }

    /**
     * @throws SarifValidationException listing the violations when the
     *                                  document is not valid SARIF 2.1.0.
     */
    public void validate(String sarifJson) {
        JSONObject document;
        try {
            document = new JSONObject(new JSONTokener(sarifJson));
        } catch (JSONException e) {
            throw new SarifValidationException(List.of("JSON mal formado: " + e.getMessage()));
        }
        try {
            schema.validate(document);
        } catch (ValidationException e) {
            List<String> violations = e.getAllMessages();
            throw new SarifValidationException(violations.size() > MAX_REPORTED_VIOLATIONS
                    ? violations.subList(0, MAX_REPORTED_VIOLATIONS)
                    : violations);
        }
    }
}
