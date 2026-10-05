package co.icesi.pdgseg.export.sarif;

import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.exception.SarifValidationException;
import co.icesi.pdgseg.export.ReportFixtures;
import co.icesi.pdgseg.export.ReportTextSanitizer;
import co.icesi.pdgseg.service.SecretMaskingService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SarifReportExporterTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SarifSchemaValidator validator = new SarifSchemaValidator();
    private SarifReportExporter exporter;
    private String sarifText;
    private JsonNode run;

    @BeforeAll
    void export() throws Exception {
        exporter = newExporter(validator);
        byte[] bytes = exporter.export(ReportFixtures.documentForSarif());
        sarifText = new String(bytes, StandardCharsets.UTF_8);
        run = mapper.readTree(bytes).path("runs").get(0);
    }

    private static SarifReportExporter newExporter(SarifSchemaValidator validator) {
        return new SarifReportExporter(new ReportTextSanitizer(new SecretMaskingService()), validator,
                "0.1.0", "https://github.com/JEGH18/segsoft-backend");
    }

    // ---- Format --------------------------------------------------------------------

    @Test
    void advertisesSarifFormatAndMediaType() {
        assertThat(exporter.format()).isEqualTo("sarif");
        assertThat(exporter.mediaType().toString()).isEqualTo("application/sarif+json");
        assertThat(exporter.fileExtension()).isEqualTo("sarif");
    }

    @Test
    void producesSchemaValidSarif210() throws Exception {
        JsonNode sarif = mapper.readTree(sarifText);
        assertThat(sarif.path("version").asText()).isEqualTo("2.1.0");
        assertThat(sarif.path("$schema").asText()).isEqualTo(SarifReportExporter.SARIF_SCHEMA_URI);
        assertThat(sarif.path("runs")).hasSize(1);
        validator.validate(sarifText); // independent re-check of the returned bytes
    }

    @Test
    void reportsFrozenWithoutARuleListAreStillValid() {
        String legacy = new String(exporter.export(ReportFixtures.documentWithSecrets()), StandardCharsets.UTF_8);
        validator.validate(legacy);
    }

    // ---- tool ------------------------------------------------------------------------

    @Test
    void identifiesTheToolByNameAndVersion() {
        JsonNode driver = run.path("tool").path("driver");
        assertThat(driver.path("name").asText()).isEqualTo("PDG-SegSoft");
        assertThat(driver.path("version").asText()).isEqualTo("0.1.0");
        assertThat(driver.path("semanticVersion").asText()).isEqualTo("0.1.0");
    }

    @Test
    void unfilteredBuildVersionFallsBackToADevVersion() throws Exception {
        SarifReportExporter unfiltered = new SarifReportExporter(new ReportTextSanitizer(new SecretMaskingService()),
                validator, "@project.version@", "https://github.com/JEGH18/segsoft-backend");
        JsonNode driver = mapper.readTree(unfiltered.export(ReportFixtures.documentForSarif()))
                .path("runs").get(0).path("tool").path("driver");
        assertThat(driver.path("version").asText()).isEqualTo("0.0.0-dev");
    }

    // ---- rules -------------------------------------------------------------------------

    @Test
    void listsEveryExecutedRuleIncludingThoseWithoutFindings() {
        List<String> ids = new ArrayList<>();
        run.path("tool").path("driver").path("rules").forEach(rule -> ids.add(rule.path("id").asText()));
        assertThat(ids).containsExactlyInAnyOrder(
                ReportFixtures.SQLI_RULE.toString(), ReportFixtures.QUIET_RULE.toString(),
                ReportFixtures.XSS_RULE.toString(), ReportFixtures.AUTH_RULE.toString(),
                ReportFixtures.DATA_RULE.toString(), ReportFixtures.DEPS_RULE.toString());
    }

    @Test
    void everyRuleHasIdNameAndAnAbsoluteHelpUri() {
        run.path("tool").path("driver").path("rules").forEach(rule -> {
            assertThat(rule.path("id").asText()).isNotBlank();
            assertThat(rule.path("name").asText()).matches("[A-Z][A-Za-z0-9]*");
            assertThat(URI.create(rule.path("helpUri").asText()).isAbsolute()).isTrue();
            assertThat(rule.path("shortDescription").path("text").asText()).isNotBlank();
            assertThat(rule.path("properties").path("tags").toString()).contains("\"security\"");
            assertThat(rule.path("properties").path("security-severity").asText()).matches("\\d+\\.\\d");
        });
    }

    @Test
    void helpUriPointsToTheCweWhenKnownAndToOwaspOtherwise() {
        assertThat(ruleById(ReportFixtures.SQLI_RULE.toString()).path("helpUri").asText())
                .isEqualTo("https://cwe.mitre.org/data/definitions/89.html");
        assertThat(ruleById(ReportFixtures.SQLI_RULE.toString()).path("properties").path("tags").toString())
                .contains("external/cwe/cwe-89");
        assertThat(ruleById(ReportFixtures.DATA_RULE.toString()).path("helpUri").asText())
                .isEqualTo("https://owasp.org/Top10/A02_2021-Cryptographic_Failures/");
    }

    // ---- results -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({"CRITICAL, error", "HIGH, error", "MEDIUM, warning", "LOW, note"})
    void mapsSeverityToSarifLevel(String severity, String level) {
        assertThat(SarifReportExporter.level(severity)).isEqualTo(level);
        run.path("results").forEach(result -> {
            if (severity.equals(result.path("properties").path("severity").asText())) {
                assertThat(result.path("level").asText()).isEqualTo(level);
            }
        });
    }

    @Test
    void containsOneResultPerFindingCoveringAllFiveCatalogCategories() {
        List<String> categories = new ArrayList<>();
        run.path("results").forEach(result -> categories.add(result.path("properties").path("category").asText()));
        assertThat(categories).containsExactlyInAnyOrder("SQL_INJECTION", "XSS", "AUTHENTICATION_FAILURE",
                "INSECURE_DATA_HANDLING", "DEPENDENCY_VULNERABILITY");
    }

    @Test
    void everyResultReferencesItsRuleConsistently() {
        JsonNode rules = run.path("tool").path("driver").path("rules");
        run.path("results").forEach(result -> {
            int index = result.path("ruleIndex").asInt();
            assertThat(rules.get(index).path("id").asText()).isEqualTo(result.path("ruleId").asText());
            assertThat(result.path("message").path("text").asText()).isNotBlank();
        });
    }

    @Test
    void locationsAreRelativeToTheRepositoryRoot() {
        List<String> uris = new ArrayList<>();
        run.path("results").forEach(result -> {
            JsonNode artifact = result.path("locations").get(0).path("physicalLocation").path("artifactLocation");
            assertThat(artifact.path("uriBaseId").asText()).isEqualTo("%SRCROOT%");
            uris.add(artifact.path("uri").asText());
        });
        assertThat(uris).containsExactlyInAnyOrder("src/main/java/com/acme/UserDao.java", "src/web/mi%20archivo.js",
                "config/settings.py", "deploy/app.yml", "requirements.txt");
        uris.forEach(uri -> assertThat(URI.create(uri).isAbsolute()).isFalse());
    }

    @Test
    void findingWithoutLineNumberHasNoRegion() {
        run.path("results").forEach(result -> {
            JsonNode physical = result.path("locations").get(0).path("physicalLocation");
            if ("deploy/app.yml".equals(physical.path("artifactLocation").path("uri").asText())) {
                assertThat(physical.has("region")).isFalse();
            } else {
                assertThat(physical.path("region").path("startLine").asInt()).isPositive();
            }
        });
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "src/main/App.java           | src/main/App.java",
            "./src/main/App.java         | src/main/App.java",
            "/src/main/App.java          | src/main/App.java",
            "src\\\\main\\\\App.java     | src/main/App.java",
            "C:\\\\repo\\\\App.java      | repo/App.java",
            "src//web/./a b.js           | src/web/a%20b.js",
            "docs/configuración.md       | docs/configuraci%C3%B3n.md",
    })
    void normalizesPathsIntoRepositoryRelativeUris(String path, String expected) {
        assertThat(SarifReportExporter.repositoryRelativeUri(path.strip().replace("\\\\", "\\")))
                .isEqualTo(expected.strip());
    }

    @Test
    void pathsEscapingTheRepositoryRootGetNoLocation() {
        assertThat(SarifReportExporter.repositoryRelativeUri("../../etc/passwd")).isNull();
        assertThat(SarifReportExporter.repositoryRelativeUri("   ")).isNull();
        assertThat(SarifReportExporter.repositoryRelativeUri(null)).isNull();
    }

    // ---- Confidentiality --------------------------------------------------------------

    @Test
    void noSecretAppearsInTheDocument() {
        assertThat(sarifText).doesNotContain(ReportFixtures.FAKE_STRIPE_KEY).contains("API_KEY = \\\"*****\\\"");
        String legacy = new String(exporter.export(ReportFixtures.documentWithSecrets()), StandardCharsets.UTF_8);
        ReportFixtures.PLANTED_SECRETS.forEach(secret -> assertThat(legacy).doesNotContain(secret));
    }

    @Test
    void gitCredentialsAreStrippedFromTheProvenance() {
        JsonNode provenance = run.path("versionControlProvenance").get(0);
        assertThat(provenance.path("repositoryUri").asText()).isEqualTo("https://github.com/acme/payments.git");
        assertThat(provenance.path("branch").asText()).isEqualTo("main");
        assertThat(sarifText).doesNotContain("ci-bot");
    }

    // ---- Validation gate ---------------------------------------------------------------

    @Test
    void anInvalidDocumentIsNeverReturned() {
        SarifSchemaValidator rejecting = mock(SarifSchemaValidator.class);
        doThrow(new SarifValidationException(List.of("#/runs/0: forced"))).when(rejecting).validate(anyString());
        SarifReportExporter gated = newExporter(rejecting);
        ReportDocument report = ReportFixtures.documentForSarif();

        assertThatThrownBy(() -> gated.export(report))
                .isInstanceOf(SarifValidationException.class)
                .satisfies(ex -> assertThat(((SarifValidationException) ex).getViolations()).containsExactly("#/runs/0: forced"));
    }

    private JsonNode ruleById(String id) {
        for (JsonNode rule : run.path("tool").path("driver").path("rules")) {
            if (id.equals(rule.path("id").asText())) {
                return rule;
            }
        }
        throw new AssertionError("Regla no encontrada: " + id);
    }
}
