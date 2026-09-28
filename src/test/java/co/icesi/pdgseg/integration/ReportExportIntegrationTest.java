package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.repository.RoleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * End-to-end export flow against a real database: a COMPLETED analysis is
 * frozen into a report, which is then exported (200), requested in an
 * unsupported format (400), requested with an unknown id (404) and, after its
 * stored content is tampered with, rejected (409).
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "sandbox.root=/tmp/pdgseg-report-integration-test",
                "cors.allowed-origins=http://localhost:5173"
        }
)
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ReportExportIntegrationTest extends PostgreSQLContainerBase {

    // Fake key, split so GitHub push protection does not flag it as real.
    private static final String PLANTED_SECRET = "sk_" + "live_51H8xQ2eZvKYlo2C0aBcDeFgHiJk";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private String auditorToken;
    private String developerToken;
    private UUID analysisId;

    @BeforeAll
    void seed() throws Exception {
        User auditor = saveUser("report_auditor_it", RoleType.AUDITOR);
        saveUser("report_dev_it", RoleType.DEVELOPER);
        auditorToken = login("report_auditor_it");
        developerToken = login("report_dev_it");

        UUID repositoryId = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO repositories (id, user_id, status, inventory_status, source_type, original_name)
                VALUES (?, ?, 'READY_FOR_ANALYSIS', 'READY_FOR_ANALYSIS', 'ZIP', 'report-it.zip')
                """, repositoryId, auditor.getId());

        analysisId = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO analyses (id, repository_id, status, rules_total, rules_executed, progress,
                                      started_at, completed_at, created_by)
                VALUES (?, ?, 'COMPLETED', 2, 2, 100, now() - interval '1 minute', now(), ?)
                """, analysisId, repositoryId, auditor.getId());

        UUID policyId = jdbcTemplate.queryForObject(
                "SELECT id FROM policies WHERE category = 'SQL_INJECTION' ORDER BY name LIMIT 1", UUID.class);
        jdbcTemplate.update("""
                INSERT INTO policy_results (analysis_id, policy_id, status, findings_count,
                                            high_or_critical_count, low_or_medium_count)
                VALUES (?, ?, 'NON_COMPLIANT', 1, 1, 0)
                """, analysisId, policyId);
        // The engine should have masked this snippet; the backend must catch it anyway.
        jdbcTemplate.update("""
                INSERT INTO findings (analysis_id, repository_id, policy_id, severity, category, file_path,
                                      line_number, evidence_snippet, cwe_id)
                VALUES (?, ?, ?, 'CRITICAL', 'SQL_INJECTION', 'src/db/UserDao.java', 42, ?, 'CWE-89')
                """, analysisId, repositoryId, policyId, "String apiKey = \"" + PLANTED_SECRET + "\";");
    }

    @Test
    void exportFlow_returns200WithAValidPdfThatHidesSecrets() throws Exception {
        UUID reportId = generateReport();

        MvcResult result = mockMvc.perform(get("/api/v1/reports/{id}/export", reportId)
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF))
                .andExpect(header().string("Content-Disposition",
                        containsString("filename=\"segsoft-report-" + reportId + ".pdf\"")))
                .andReturn();

        byte[] pdf = result.getResponse().getContentAsByteArray();
        try (PDDocument document = Loader.loadPDF(pdf)) {
            PDFTextStripper stripper = new PDFTextStripper();
            stripper.setSortByPosition(true);
            String text = stripper.getText(document).replaceAll("\\s+", "");
            assertThat(text)
                    .contains("report-it.zip")
                    .contains("1.Resumenejecutivo")
                    .contains("4.Hallazgosdetallados")
                    .contains("src/db/UserDao.java:42")
                    .contains("apiKey=\"*****\"")
                    .doesNotContain(PLANTED_SECRET);
        }
    }

    @Test
    void unsupportedFormat_returns400ListingSupportedFormats() throws Exception {
        UUID reportId = generateReport();

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId)
                        .param("format", "docx")
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("UNSUPPORTED_FORMAT"))
                .andExpect(jsonPath("$.supportedFormats[0]").value("pdf"));
    }

    @Test
    void unknownReport_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/reports/{id}/export", UUID.randomUUID())
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isNotFound());
    }

    @Test
    void tamperedReport_returns409AndNoFile() throws Exception {
        UUID reportId = generateReport();
        jdbcTemplate.update("UPDATE reports SET content_json = replace(content_json, 'CRITICAL', 'LOW') WHERE id = ?",
                reportId);

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId)
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + auditorToken))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("REPORT_INTEGRITY_ERROR"))
                .andExpect(header().doesNotExist("Content-Disposition"));
    }

    @Test
    void developer_cannotExport() throws Exception {
        UUID reportId = generateReport();

        mockMvc.perform(get("/api/v1/reports/{id}/export", reportId)
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + developerToken))
                .andExpect(status().isForbidden());
    }

    private UUID generateReport() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/reports")
                        .header("Authorization", "Bearer " + auditorToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"analysisId\":\"" + analysisId + "\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        Map<?, ?> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        return UUID.fromString((String) body.get("id"));
    }

    private User saveUser(String username, RoleType roleType) {
        // RoleRepository.findByName(String) does not match the enum-typed column,
        // so the role is looked up in memory.
        Role role = roleRepository.findAll().stream()
                .filter(candidate -> candidate.getName() == roleType)
                .findFirst()
                .orElseThrow();
        User user = userRepository.findByUsername(username).orElse(new User());
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode("report_pass123!"));
        user.setEnabled(true);
        user.setFailedAttempts(0);
        user.setRoles(Set.of(role));
        return userRepository.saveAndFlush(user);
    }

    private String login(String username) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", username, "password", "report_pass123!"))))
                .andExpect(status().isOk())
                .andReturn();
        Map<?, ?> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        return (String) body.get("accessToken");
    }
}
