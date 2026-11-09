package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V38 against a real PostgreSQL: the rules seeded by V14 and V27 get random ids, so the
 * fixes of V18/V19/V29 (WHERE id = '...') never reached them in a database created from
 * scratch. V38 finds them by content. Each test inserts the rows as a fresh database has
 * them, runs the migration script again and rolls everything back.
 */
@SpringBootTest(
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "cors.allowed-origins=http://localhost:5173"
        }
)
@Transactional
class SuggestedActionMigrationIntegrationTest extends PostgreSQLContainerBase {

    private static final String MIGRATION = "db/migration/V38__suggested_actions_by_rule_content.sql";
    private static final String SQL_CONCAT_PAYLOAD =
            "{\"pattern\": \"(Statement|createStatement|executeQuery)\\\\s*\\\\(.*\\\\+\", "
                    + "\"description\": \"Concatenación directa de cadenas en query SQL\"}";

    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private UserRepository userRepository;
    @Autowired private ObjectMapper objectMapper;

    private UUID policyId;

    @BeforeEach
    void setUp() {
        policyId = jdbcTemplate.queryForObject("""
                INSERT INTO policies (name, description, category, framework, status, version, weight, created_at)
                VALUES ('Política V38 IT', 'Política para probar la migración V38', 'SQL_INJECTION',
                        'OWASP_TOP_10_2021', 'ACTIVE', 1, 50, now()) RETURNING id
                """, UUID.class);
    }

    @Test
    void seededRuleWithoutRecommendationGetsTheOneForItsContent() throws Exception {
        UUID ruleId = insertRule("PATTERN_REGEX", SQL_CONCAT_PAYLOAD);

        runMigration();

        JsonNode payload = payloadOf(ruleId);
        assertThat(payload.path("suggestedAction").asText()).startsWith("Usa sentencias parametrizadas");
        assertThat(payload.path("pattern").asText()).isEqualTo("(Statement|createStatement|executeQuery)\\s*\\(.*\\+");
    }

    @Test
    void ruleThatAlreadyHasARecommendationKeepsIt() throws Exception {
        UUID ruleId = insertRule("PATTERN_REGEX",
                SQL_CONCAT_PAYLOAD.replace("}", ", \"suggestedAction\": \"Texto editado por un admin\"}"));

        runMigration();

        assertThat(payloadOf(ruleId).path("suggestedAction").asText()).isEqualTo("Texto editado por un admin");
    }

    @Test
    void brokenPipAuditPayloadBecomesValidJsonWithItsRecommendation() throws Exception {
        // What V27 leaves in a fresh database: two JSON objects glued together.
        UUID ruleId = insertRule("DEPENDENCY_CHECK",
                "{\"tool\": \"pip-audit\", \"description\": \"Escaneo de CVEs en dependencias Python del proyecto\"}"
                        + "{\"suggestedAction\": \"x\"}");

        runMigration();

        JsonNode payload = payloadOf(ruleId);
        assertThat(payload.path("suggestedAction").asText()).startsWith("Ejecuta pip-audit");
        assertThat(payload.path("description").asText()).isEqualTo("Escaneo de CVEs en dependencias Python del proyecto");
    }

    @Test
    void findingSavedWithoutRecommendationTakesTheOneOfItsRule() {
        UUID ruleId = insertRule("PATTERN_REGEX", SQL_CONCAT_PAYLOAD);
        UUID findingId = insertFinding(ruleId);

        runMigration();

        assertThat(jdbcTemplate.queryForObject("SELECT suggested_action FROM findings WHERE id = ?",
                String.class, findingId)).startsWith("Usa sentencias parametrizadas");
    }

    @Test
    void runningItTwiceChangesNothingTheSecondTime() {
        UUID ruleId = insertRule("PATTERN_REGEX", SQL_CONCAT_PAYLOAD);
        runMigration();
        String once = jdbcTemplate.queryForObject("SELECT payload FROM rules WHERE id = ?", String.class, ruleId);

        runMigration();

        assertThat(jdbcTemplate.queryForObject("SELECT payload FROM rules WHERE id = ?", String.class, ruleId))
                .isEqualTo(once);
    }

    // ---- helpers ---------------------------------------------------------------------------

    private void runMigration() {
        try {
            jdbcTemplate.execute(new ClassPathResource(MIGRATION).getContentAsString(StandardCharsets.UTF_8));
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private UUID insertRule(String type, String payload) {
        return jdbcTemplate.queryForObject("""
                INSERT INTO rules (policy_id, type, payload, severity, cwe_id, category, languages)
                VALUES (?, ?, ?, 'CRITICAL', 'CWE-89', 'SQL_INJECTION', '["java"]'::jsonb) RETURNING id
                """, UUID.class, policyId, type, payload);
    }

    private JsonNode payloadOf(UUID ruleId) throws Exception {
        return objectMapper.readTree(
                jdbcTemplate.queryForObject("SELECT payload FROM rules WHERE id = ?", String.class, ruleId));
    }

    private UUID insertFinding(UUID ruleId) {
        User owner = userRepository.findByUsername("v38_migration_it").orElse(new User());
        owner.setUsername("v38_migration_it");
        owner.setPasswordHash("not-used");
        owner.setEnabled(true);
        owner.setFailedAttempts(0);
        owner = userRepository.saveAndFlush(owner);

        UUID repositoryId = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO repositories (id, user_id, status, inventory_status, source_type, original_name)
                VALUES (?, ?, 'READY_FOR_ANALYSIS', 'READY_FOR_ANALYSIS', 'ZIP', 'v38-it.zip')
                """, repositoryId, owner.getId());
        UUID analysisId = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO analyses (id, repository_id, status, rules_total, rules_executed, progress,
                                      started_at, completed_at, created_by)
                VALUES (?, ?, 'COMPLETED', 1, 1, 100, now() - interval '1 minute', now(), ?)
                """, analysisId, repositoryId, owner.getId());
        UUID findingId = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO findings (id, analysis_id, repository_id, policy_id, rule_id, severity, category,
                                      file_path, line_number, evidence_snippet, cwe_id, suggested_action)
                VALUES (?, ?, ?, ?, ?, 'CRITICAL', 'SQL_INJECTION', 'src/Dao.java', 7, 'executeQuery("" + id)',
                        'CWE-89', NULL)
                """, findingId, analysisId, repositoryId, policyId, ruleId);
        return findingId;
    }
}
