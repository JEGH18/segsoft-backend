package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.repository.RoleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.InputStream;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * HU "Generar reporte estructurado de cumplimiento" against a real
 * PostgreSQL: generation endpoint, structured content and its JSON Schema,
 * 422 for analyses that are not completed, append-only table, immutability
 * after the analysis/policies change, checksum detection of a manipulated
 * JSONB column and the per-repository history.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "sandbox.root=/tmp/pdgseg-structured-report-it",
                "report.export.cache.dir=${java.io.tmpdir}/pdgseg-export-cache-structured-it",
                "cors.allowed-origins=http://localhost:5173"
        }
)
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StructuredReportIntegrationTest extends PostgreSQLContainerBase {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private User auditor;
    private String auditorToken;
    private UUID policyId;
    private Schema reportSchema;

    private record Seeded(UUID repositoryId, UUID analysisId, UUID findingId) {
    }

    @BeforeAll
    void setUp() throws Exception {
        Role role = roleRepository.findAll().stream()
                .filter(candidate -> candidate.getName() == RoleType.AUDITOR).findFirst().orElseThrow();
        auditor = userRepository.findByUsername("structured_auditor_it").orElse(new User());
        auditor.setUsername("structured_auditor_it");
        auditor.setPasswordHash(passwordEncoder.encode("structured_pass123!"));
        auditor.setEnabled(true);
        auditor.setFailedAttempts(0);
        auditor.setRoles(Set.of(role));
        auditor = userRepository.saveAndFlush(auditor);
        auditorToken = login();

        policyId = jdbcTemplate.queryForObject(
                "SELECT id FROM policies WHERE category = 'SQL_INJECTION' AND framework IS NOT NULL ORDER BY name LIMIT 1",
                UUID.class);
        try (InputStream in = getClass().getResourceAsStream("/report/structured-report.schema.json")) {
            reportSchema = SchemaLoader.builder().draftV7Support().schemaJson(new JSONObject(new JSONTokener(in)))
                    .build().load().build();
        }
    }

    // ---- Scenario 1: generation ------------------------------------------------------

    @Test
    void generatingFromACompletedAnalysisReturns201WithTheReportUrlAndStoresItAsGenerated() throws Exception {
        Seeded seeded = seed("COMPLETED");

        MvcResult result = mockMvc.perform(post("/api/v1/analyses/{id}/reports", seeded.analysisId())
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", startsWith("/api/v1/reports/")))
                .andExpect(jsonPath("$.status").value("GENERATED"))
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        UUID reportId = UUID.fromString(body.path("id").asText());
        assertThat(result.getResponse().getHeader("Location")).isEqualTo("/api/v1/reports/" + reportId);
        assertThat(body.path("url").asText()).isEqualTo("/api/v1/reports/" + reportId);

        Map<String, Object> row = jdbcTemplate.queryForMap(
                "SELECT status, analysis_id, pg_typeof(content)::text AS content_type, length(checksum) AS checksum_length "
                        + "FROM reports WHERE id = ?", reportId);
        assertThat(row.get("status")).isEqualTo("GENERATED");
        assertThat(row.get("analysis_id")).isEqualTo(seeded.analysisId());
        assertThat(row.get("content_type")).isEqualTo("jsonb");
        assertThat(row.get("checksum_length")).isEqualTo(64);
    }

    // ---- Scenario 2: structure ---------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"technical", "executive"})
    void theReportHasEverySectionAndMatchesItsJsonSchema(String view) throws Exception {
        UUID reportId = generate(seed("COMPLETED").analysisId());

        JsonNode report = getReport(reportId, view);

        reportSchema.validate(new JSONObject(report.toString()));
        assertThat(report.fieldNames()).toIterable().contains("metadata", "executiveSummary", "findingsBySeverity",
                "claudeCodeSecurityCoverage", "frameworkCoverage", "traceabilityReference");
        assertThat(report.path("metadata").path("repoName").asText()).isEqualTo("structured-it.zip");
        assertThat(report.path("metadata").path("generatedBy").asText()).isEqualTo("structured_auditor_it");
        assertThat(report.path("claudeCodeSecurityCoverage")).hasSize(5);
        assertThat(report.path("findingsBySeverity").path("CRITICAL").path("count").asInt()).isEqualTo(1);
        if (view.equals("technical")) {
            assertThat(report.path("policyResults")).hasSize(1);
            assertThat(report.path("findingsBySeverity").path("CRITICAL").path("findings").get(0)
                    .path("evidenceSnippet").asText()).isEqualTo("password=*****");
        } else {
            assertThat(report.has("policyResults")).isFalse();
            assertThat(report.toString()).doesNotContain("evidenceSnippet");
        }
    }

    // ---- Scenario 3: only completed analyses --------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"CANCELLED", "FAILED", "RUNNING", "QUEUED"})
    void analysesThatAreNotCompletedAreRejectedWith422(String status) throws Exception {
        Seeded seeded = seed(status);

        mockMvc.perform(post("/api/v1/analyses/{id}/reports", seeded.analysisId())
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message").value(
                        "Solo se pueden generar reportes de análisis completados (estado actual: " + status + ")"));
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM reports WHERE analysis_id = ?", Long.class,
                seeded.analysisId())).isZero();
    }

    // ---- Scenario 4: immutability -------------------------------------------------------

    @Test
    void laterChangesToTheAnalysisOrPoliciesNeverReachTheReport() throws Exception {
        Seeded seeded = seed("COMPLETED");
        UUID reportId = generate(seeded.analysisId());
        JsonNode before = getReport(reportId, "technical");
        String policyName = jdbcTemplate.queryForObject("SELECT name FROM policies WHERE id = ?", String.class, policyId);

        try {
            jdbcTemplate.update("UPDATE findings SET severity = 'LOW', evidence_snippet = 'cambiado' WHERE id = ?",
                    seeded.findingId());
            jdbcTemplate.update("UPDATE policy_results SET status = 'COMPLIANT' WHERE analysis_id = ?", seeded.analysisId());
            jdbcTemplate.update("UPDATE policies SET name = name || ' (editada)' WHERE id = ?", policyId);
            jdbcTemplate.update("UPDATE repositories SET original_name = 'renombrado.zip' WHERE id = ?",
                    seeded.repositoryId());

            JsonNode after = getReport(reportId, "technical");

            assertThat(after).isEqualTo(before);
            assertThat(after.path("policyResults").get(0).path("status").asText()).isEqualTo("NON_COMPLIANT");
            assertThat(after.path("metadata").path("repoName").asText()).isEqualTo("structured-it.zip");
        } finally {
            jdbcTemplate.update("UPDATE policies SET name = ? WHERE id = ?", policyName, policyId);
        }
    }

    @Test
    void theReportsTableIsAppendOnly() throws Exception {
        UUID reportId = generate(seed("COMPLETED").analysisId());
        String content = jdbcTemplate.queryForObject("SELECT content::text FROM reports WHERE id = ?", String.class, reportId);

        assertThatThrownBy(() -> jdbcTemplate.update(
                "UPDATE reports SET content = jsonb_set(content, '{summary,totalFindings}', '0') WHERE id = ?", reportId))
                .isInstanceOf(DataAccessException.class)
                .hasMessageContaining("append-only");
        assertThatThrownBy(() -> jdbcTemplate.update("UPDATE reports SET checksum = ? WHERE id = ?", "0".repeat(64), reportId))
                .hasMessageContaining("append-only");
        assertThatThrownBy(() -> jdbcTemplate.update("DELETE FROM reports WHERE id = ?", reportId))
                .hasMessageContaining("append-only");

        assertThat(jdbcTemplate.queryForObject("SELECT content::text FROM reports WHERE id = ?", String.class, reportId))
                .isEqualTo(content);
    }

    @Test
    void deletingTheRepositoryKeepsTheReportIntactAndVerifiable() throws Exception {
        Seeded seeded = seed("COMPLETED");
        UUID reportId = generate(seeded.analysisId());

        // Cascades to the analysis; reports.analysis_id is set to NULL, the only change the trigger allows.
        jdbcTemplate.update("DELETE FROM repositories WHERE id = ?", seeded.repositoryId());

        assertThat(jdbcTemplate.queryForObject("SELECT analysis_id FROM reports WHERE id = ?", UUID.class, reportId)).isNull();
        JsonNode report = getReport(reportId, "technical");
        assertThat(report.path("integrityVerified").asBoolean()).isTrue();
        assertThat(report.path("metadata").path("analysisId").asText()).isEqualTo(seeded.analysisId().toString());
        assertThat(report.path("metadata").path("repoName").asText()).isEqualTo("structured-it.zip");
    }

    // ---- Integrity ------------------------------------------------------------------------

    @Test
    void aManipulatedContentColumnIsDetectedByItsChecksum() throws Exception {
        UUID reportId = generate(seed("COMPLETED").analysisId());

        jdbcTemplate.execute("ALTER TABLE reports DISABLE TRIGGER trg_reports_append_only");
        try {
            jdbcTemplate.update("UPDATE reports SET content = jsonb_set(content, '{summary,compliancePercentage}', '100') "
                    + "WHERE id = ?", reportId);
        } finally {
            jdbcTemplate.execute("ALTER TABLE reports ENABLE TRIGGER trg_reports_append_only");
        }

        mockMvc.perform(get("/api/v1/reports/{id}", reportId).header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("REPORT_INTEGRITY_ERROR"));
        assertThat(jdbcTemplate.queryForObject(
                "SELECT count(*) FROM auth_audit_log WHERE event_type = 'REPORT_INTEGRITY_VIOLATION' AND details->>'reportId' = ?",
                Long.class, reportId.toString())).isPositive();
    }

    // ---- History --------------------------------------------------------------------------

    @Test
    void historyCanBeFilteredByRepository() throws Exception {
        Seeded seeded = seed("COMPLETED");
        UUID first = generate(seeded.analysisId());
        UUID second = generate(seeded.analysisId());
        generate(seed("COMPLETED").analysisId()); // another repository

        mockMvc.perform(get("/api/v1/reports").param("repositoryId", seeded.repositoryId().toString())
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.content[0].id").value(second.toString()))
                .andExpect(jsonPath("$.content[1].id").value(first.toString()));
    }

    // ---- helpers ---------------------------------------------------------------------------

    private Seeded seed(String status) {
        UUID repositoryId = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO repositories (id, user_id, status, inventory_status, source_type, original_name)
                VALUES (?, ?, 'READY_FOR_ANALYSIS', 'READY_FOR_ANALYSIS', 'ZIP', 'structured-it.zip')
                """, repositoryId, auditor.getId());
        UUID analysisId = UUID.randomUUID();
        boolean completed = status.equals("COMPLETED");
        jdbcTemplate.update("""
                INSERT INTO analyses (id, repository_id, status, rules_total, rules_executed, progress,
                                      started_at, completed_at, created_by)
                VALUES (?, ?, ?, 1, 1, 100, now() - interval '1 minute', CASE WHEN ? THEN now() END, ?)
                """, analysisId, repositoryId, status, completed, auditor.getId());
        UUID findingId = UUID.randomUUID();
        if (completed) {
            jdbcTemplate.update("""
                    INSERT INTO policy_results (analysis_id, policy_id, status, findings_count,
                                                high_or_critical_count, low_or_medium_count)
                    VALUES (?, ?, 'NON_COMPLIANT', 1, 1, 0)
                    """, analysisId, policyId);
            jdbcTemplate.update("""
                    INSERT INTO findings (id, analysis_id, repository_id, policy_id, severity, category, file_path,
                                          line_number, evidence_snippet, cwe_id, suggested_action)
                    VALUES (?, ?, ?, ?, 'CRITICAL', 'SQL_INJECTION', 'src/db/Dao.java', 7, 'password=hunter2',
                            'CWE-89', 'Usar PreparedStatement')
                    """, findingId, analysisId, repositoryId, policyId);
        }
        return new Seeded(repositoryId, analysisId, findingId);
    }

    private UUID generate(UUID analysisId) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/analyses/{id}/reports", analysisId)
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(objectMapper.readTree(result.getResponse().getContentAsString()).path("id").asText());
    }

    private JsonNode getReport(UUID reportId, String view) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/reports/{id}", reportId).param("view", view)
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private String login() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", "structured_auditor_it", "password", "structured_pass123!"))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("accessToken").asText();
    }
}
