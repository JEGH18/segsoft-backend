package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.response.StructuredReportResponse;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.export.ReportFixtures;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.io.InputStream;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Contract of GET /api/v1/reports/{id}: the structured report, in both views,
 * validates against src/main/resources/report/structured-report.schema.json.
 * Runs in the CI pipeline (.github/workflows/ci-backend.yml).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StructuredReportSchemaTest {

    static final String SCHEMA = "/report/structured-report.schema.json";

    /** Configured like Spring Boot's: dates as ISO-8601 strings, as the API sends them. */
    private final ObjectMapper objectMapper = Jackson2ObjectMapperBuilder.json()
            .featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS).build();
    private final StructuredReportMapper mapper = new StructuredReportMapper(new SecretMaskingService());
    private Schema schema;

    @BeforeAll
    void loadSchema() throws Exception {
        try (InputStream in = StructuredReportSchemaTest.class.getResourceAsStream(SCHEMA)) {
            schema = SchemaLoader.builder().draftV7Support().schemaJson(new JSONObject(new JSONTokener(in)))
                    .build().load().build();
        }
    }

    private JsonNode render(ReportContent content, ReportView view) throws Exception {
        Report report = new Report();
        report.setId(UUID.randomUUID());
        report.setStatus(ReportStatus.GENERATED);
        report.setChecksum("ab".repeat(32));
        report.setGeneratedAt(OffsetDateTime.now());
        StructuredReportResponse response = mapper.toResponse(report, content, view, List.of("pdf", "sarif"));
        return objectMapper.readTree(objectMapper.writeValueAsString(response));
    }

    private void validate(JsonNode document) {
        schema.validate(new JSONObject(document.toString()));
    }

    @ParameterizedTest
    @EnumSource(ReportView.class)
    void currentReportsMatchTheSchema(ReportView view) throws Exception {
        assertThatCode(() -> validate(render(ReportFixtures.documentForSarif().content(), view)))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @EnumSource(ReportView.class)
    void reportsFrozenBeforeSchemaV3StillMatch(ReportView view) throws Exception {
        assertThatCode(() -> validate(render(ReportFixtures.documentWithSecrets().content(), view)))
                .doesNotThrowAnyException();
        assertThatCode(() -> validate(render(ReportFixtures.emptyDocument().content(), view)))
                .doesNotThrowAnyException();
    }

    @Test
    void everyRequiredSectionIsPresent() throws Exception {
        JsonNode technical = render(ReportFixtures.documentForSarif().content(), ReportView.TECHNICAL);
        assertThat(technical.fieldNames()).toIterable().contains("metadata", "executiveSummary", "policyResults",
                "findingsBySeverity", "claudeCodeSecurityCoverage", "frameworkCoverage", "traceabilityReference");
        assertThat(technical.path("metadata").fieldNames()).toIterable()
                .contains("reportId", "analysisId", "generatedAt", "generatedBy", "repoName");
    }

    @Test
    void theExecutiveViewCarriesNoSnippetsOrPerPolicyDetail() throws Exception {
        JsonNode executive = render(ReportFixtures.documentForSarif().content(), ReportView.EXECUTIVE);
        assertThat(executive.has("policyResults")).isFalse();
        executive.path("findingsBySeverity").forEach(group -> assertThat(group.has("findings")).isFalse());
        assertThat(executive.toString()).doesNotContain("evidenceSnippet").doesNotContain("innerHTML");
        assertThat(executive.path("executiveSummary").path("recommendations").isArray()).isTrue();
        assertThat(executive.path("claudeCodeSecurityCoverage")).hasSize(5);
    }

    @Test
    void theSchemaRejectsAnExecutiveViewThatLeaksFindings() throws Exception {
        ObjectNode executive = (ObjectNode) render(ReportFixtures.documentForSarif().content(), ReportView.EXECUTIVE);
        JsonNode technical = render(ReportFixtures.documentForSarif().content(), ReportView.TECHNICAL);
        ((ObjectNode) executive.path("findingsBySeverity")).set("CRITICAL", technical.path("findingsBySeverity").path("CRITICAL"));

        assertThatThrownBy(() -> validate(executive)).isInstanceOf(ValidationException.class);
    }

    @Test
    void theSchemaRejectsATechnicalViewWithoutPolicyResultsOrCoverage() throws Exception {
        ObjectNode technical = (ObjectNode) render(ReportFixtures.documentForSarif().content(), ReportView.TECHNICAL);
        technical.remove("policyResults");
        assertThatThrownBy(() -> validate(technical)).isInstanceOf(ValidationException.class);

        ObjectNode partialCoverage = (ObjectNode) render(ReportFixtures.documentForSarif().content(), ReportView.TECHNICAL);
        ((com.fasterxml.jackson.databind.node.ArrayNode) partialCoverage.path("claudeCodeSecurityCoverage")).remove(0);
        assertThatThrownBy(() -> validate(partialCoverage)).isInstanceOf(ValidationException.class);
    }
}
