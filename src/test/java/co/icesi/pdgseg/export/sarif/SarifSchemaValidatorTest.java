package co.icesi.pdgseg.export.sarif;

import co.icesi.pdgseg.exception.SarifValidationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SarifSchemaValidatorTest {

    private final SarifSchemaValidator validator = new SarifSchemaValidator();

    @Test
    void bundlesTheOfficialSchema() throws IOException {
        try (InputStream schema = SarifSchemaValidator.class.getResourceAsStream(SarifSchemaValidator.SCHEMA_RESOURCE)) {
            assertThat(schema).isNotNull();
            assertThat(new String(schema.readAllBytes(), StandardCharsets.UTF_8))
                    .contains("Static Analysis Results Format (SARIF) Version 2.1.0 JSON Schema");
        }
    }

    @Test
    void acceptsAValidSarifDocument() {
        assertThatCode(() -> validator.validate(resource("valid-minimal.sarif"))).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @CsvSource({
            "invalid-level.sarif,           critical",
            "invalid-start-line.sarif,      startLine",
            "invalid-missing-version.sarif, version",
    })
    void rejectsDocumentsThatBreakTheSchema(String file, String expectedInViolation) {
        assertThatThrownBy(() -> validator.validate(resource(file)))
                .isInstanceOf(SarifValidationException.class)
                .satisfies(ex -> assertThat(((SarifValidationException) ex).getViolations())
                        .isNotEmpty()
                        .anySatisfy(violation -> assertThat(violation).contains(expectedInViolation)));
    }

    @Test
    void rejectsMalformedJson() {
        assertThatThrownBy(() -> validator.validate("{\"version\": \"2.1.0\", \"runs\": ["))
                .isInstanceOf(SarifValidationException.class)
                .satisfies(ex -> assertThat(((SarifValidationException) ex).getViolations().get(0))
                        .startsWith("JSON mal formado"));
    }

    private static String resource(String name) throws IOException {
        try (InputStream in = SarifSchemaValidatorTest.class.getResourceAsStream("/sarif/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
