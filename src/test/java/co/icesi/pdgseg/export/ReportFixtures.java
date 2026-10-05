package co.icesi.pdgseg.export;

import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.CategoryCoverage;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Metadata;
import co.icesi.pdgseg.dto.report.ReportContent.PolicyEntry;
import co.icesi.pdgseg.dto.report.ReportContent.RuleEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Summary;
import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.service.ReportGeneratorService;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Report fixtures shared by the exporter tests. The findings deliberately
 * carry secrets the engine failed to mask, so the tests can prove the
 * exporter's own masking catches them.
 */
public final class ReportFixtures {

    public static final String CHECKSUM = "9f2c4e1b7a3d5f60c8e9b1a2d3c4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6";
    public static final String REPOSITORY_NAME = "acme-payments";

    /**
     * Fake Stripe-style key. Split so the literal never appears in source:
     * GitHub push protection would otherwise reject it as a real secret.
     */
    public static final String FAKE_STRIPE_KEY = "sk_" + "live_51H8xQ2eZvKYlo2C0aBcDeFgHiJk";

    /** Secrets planted in the fixture that must never appear in an exported file. */
    public static final List<String> PLANTED_SECRETS = List.of(
            FAKE_STRIPE_KEY,
            "AKIAIOSFODNN7EXAMPLE",
            "hunter2-Sup3rS3cret",
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXNlY3JldA",
            "MIIEpAIBAAKCAQEA7secretkeymaterial",
            "Zw5ecretValue"
    );

    private ReportFixtures() {
    }

    public static ReportDocument documentWithSecrets() {
        OffsetDateTime started = OffsetDateTime.of(2026, 9, 28, 6, 16, 35, 0, ZoneOffset.UTC);
        Metadata metadata = new Metadata(
                UUID.fromString("85db2d64-9c6f-4dd2-8eb0-254ab3496a8d"),
                UUID.fromString("4a46f591-fbff-4749-baff-439e7d274c05"),
                REPOSITORY_NAME,
                "GIT",
                "https://ci-bot:ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789@github.com/acme/payments.git",
                "main",
                null,
                started,
                started.plusSeconds(42),
                24,
                24,
                "auditor",
                started.plusMinutes(5)
        );

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        bySeverity.put("CRITICAL", 1);
        bySeverity.put("HIGH", 1);
        bySeverity.put("MEDIUM", 2);
        bySeverity.put("LOW", 1);
        Summary summary = new Summary(new BigDecimal("60.00"), new BigDecimal("55.50"),
                5, 3, 1, 1, 5, bySeverity, 1);

        // DEPENDENCY_VULNERABILITY and INSECURE_DATA_HANDLING are left out on
        // purpose: the exporter must still list all five catalog categories.
        List<CategoryCoverage> coverage = List.of(
                new CategoryCoverage("SQL_INJECTION", 2, 1, 1, 0, 2, 1),
                new CategoryCoverage("XSS", 1, 1, 0, 0, 1, 0),
                new CategoryCoverage("AUTHENTICATION_FAILURE", 2, 1, 0, 1, 2, 1)
        );

        List<PolicyEntry> policies = List.of(
                policy("Validación de entradas antes de construir consultas SQL", "SQL_INJECTION", "COMPLIANT", 0),
                policy("Consultas parametrizadas obligatorias", "SQL_INJECTION", "NON_COMPLIANT", 2),
                policy("Content Security Policy obligatoria", "XSS", "COMPLIANT", 1),
                policy("Gestión segura de credenciales de autenticación", "AUTHENTICATION_FAILURE", "REQUIRES_REVIEW", 2),
                policy("Tokens JWT con expiración y rotación", "AUTHENTICATION_FAILURE", "COMPLIANT", 0)
        );

        // Intentionally not in severity order.
        List<FindingEntry> findings = List.of(
                finding("LOW", "XSS", "src/web/banner.js", 3,
                        "const apiKey = \"" + FAKE_STRIPE_KEY + "\";"),
                finding("CRITICAL", "SQL_INJECTION", "src/db/UserDao.java", 42,
                        "String q = \"SELECT * FROM users WHERE id=\" + id; // api_key=*****"),
                finding("MEDIUM", "AUTHENTICATION_FAILURE", "config/app.yml", 7,
                        "aws:\n  access_id: AKIAIOSFODNN7EXAMPLE\n  password: \"hunter2-Sup3rS3cret\""),
                finding("HIGH", "SQL_INJECTION", "src/db/OrderDao.java", 88,
                        "headers.put(\"Authorization\", \"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXNlY3JldA\");"),
                finding("MEDIUM", "AUTHENTICATION_FAILURE", "keys/‮deploy.pem", 1,
                        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7secretkeymaterial\n-----END RSA PRIVATE KEY-----\n"
                                + "db_pass​word=Zw5ecretValue\0")
        );

        // Schema v1 (no rule list), as frozen before the SARIF export existed.
        ReportContent content = new ReportContent(1, metadata, summary, coverage, policies, findings, null, null, null);
        return new ReportDocument(UUID.fromString("0f8f7c1e-4c1a-4f3e-9d7a-2b6c1d0e9a11"), "GENERATED",
                CHECKSUM, started.plusMinutes(5), content);
    }

    public static ReportDocument emptyDocument() {
        ReportDocument base = documentWithSecrets();
        ReportContent content = base.content();
        Summary summary = new Summary(BigDecimal.ZERO, BigDecimal.ZERO, 0, 0, 0, 0, 0,
                Map.of("CRITICAL", 0, "HIGH", 0, "MEDIUM", 0, "LOW", 0), 0);
        return new ReportDocument(base.reportId(), base.status(), base.checksum(), base.generatedAt(),
                new ReportContent(content.schemaVersion(), content.metadata(), summary, List.of(), List.of(), List.of(),
                        List.of(), List.of(), List.of()));
    }

    // ---- SARIF ------------------------------------------------------------------------

    public static final UUID SQLI_RULE = UUID.fromString("11111111-0000-0000-0000-000000000001");
    public static final UUID XSS_RULE = UUID.fromString("11111111-0000-0000-0000-000000000002");
    public static final UUID AUTH_RULE = UUID.fromString("11111111-0000-0000-0000-000000000003");
    public static final UUID DATA_RULE = UUID.fromString("11111111-0000-0000-0000-000000000004");
    public static final UUID DEPS_RULE = UUID.fromString("11111111-0000-0000-0000-000000000005");
    /** Executed by the analysis but produced no finding. */
    public static final UUID QUIET_RULE = UUID.fromString("11111111-0000-0000-0000-000000000006");

    /**
     * A schema-v2 report with one finding per catalog category, the rule
     * list frozen at generation time, a Windows-style path with a space, a
     * finding without line number and a secret the engine failed to mask.
     */
    public static ReportDocument documentForSarif() {
        ReportDocument base = documentWithSecrets();
        UUID sqlPolicy = UUID.fromString("22222222-0000-0000-0000-000000000001");
        UUID xssPolicy = UUID.fromString("22222222-0000-0000-0000-000000000002");
        UUID authPolicy = UUID.fromString("22222222-0000-0000-0000-000000000003");
        UUID dataPolicy = UUID.fromString("22222222-0000-0000-0000-000000000004");
        UUID depsPolicy = UUID.fromString("22222222-0000-0000-0000-000000000005");

        List<RuleEntry> rules = List.of(
                new RuleEntry(SQLI_RULE, sqlPolicy, "Consultas parametrizadas obligatorias", "PATTERN_REGEX",
                        "CRITICAL", "SQL_INJECTION", "CWE-89", "Concatenación directa de cadenas en query SQL"),
                new RuleEntry(QUIET_RULE, sqlPolicy, "Consultas parametrizadas obligatorias", "PATTERN_REGEX",
                        "MEDIUM", "SQL_INJECTION", "CWE-89", "Consulta SELECT * sin filtro de columnas sensibles"),
                new RuleEntry(XSS_RULE, xssPolicy, "Codificación de salida HTML", "PATTERN_REGEX",
                        "HIGH", "XSS", "CWE-79", "Asignación directa a innerHTML sin escape"),
                new RuleEntry(AUTH_RULE, authPolicy, "No almacenar secretos en código fuente", "PATTERN_REGEX",
                        "HIGH", "AUTHENTICATION_FAILURE", "CWE-798", "Credenciales embebidas en el código"),
                new RuleEntry(DATA_RULE, dataPolicy, "Cifrado de datos sensibles en reposo", "CONFIG_CHECK",
                        "MEDIUM", "INSECURE_DATA_HANDLING", null, "Datos sensibles almacenados sin cifrado"),
                new RuleEntry(DEPS_RULE, depsPolicy, "Remediación oportuna de vulnerabilidades en componentes",
                        "DEPENDENCY_CHECK", "LOW", "DEPENDENCY_VULNERABILITY", "CWE-1104",
                        "Dependencia con vulnerabilidad conocida")
        );

        List<FindingEntry> findings = List.of(
                sarifFinding(DEPS_RULE, depsPolicy, "Remediación oportuna de vulnerabilidades en componentes", "LOW",
                        "DEPENDENCY_VULNERABILITY", "CWE-1104", "requirements.txt", 3, "requests==2.19.0",
                        "Actualizar requests a 2.32.0 o superior."),
                sarifFinding(SQLI_RULE, sqlPolicy, "Consultas parametrizadas obligatorias", "CRITICAL",
                        "SQL_INJECTION", "CWE-89", "src/main/java/com/acme/UserDao.java", 42,
                        "stmt.executeQuery(\"SELECT * FROM users WHERE id=\" + id);",
                        "Usar PreparedStatement con parámetros."),
                sarifFinding(XSS_RULE, xssPolicy, "Codificación de salida HTML", "HIGH", "XSS", "CWE-79",
                        "./src\\web\\mi archivo.js", 18, "panel.innerHTML = userInput;",
                        "Usar textContent o sanitizar con DOMPurify."),
                sarifFinding(AUTH_RULE, authPolicy, "No almacenar secretos en código fuente", "HIGH",
                        "AUTHENTICATION_FAILURE", "CWE-798", "config/settings.py", 7,
                        "API_KEY = \"" + FAKE_STRIPE_KEY + "\"", "Mover la clave a un gestor de secretos."),
                sarifFinding(DATA_RULE, dataPolicy, "Cifrado de datos sensibles en reposo", "MEDIUM",
                        "INSECURE_DATA_HANDLING", null, "deploy/app.yml", null, null,
                        "Habilitar cifrado en reposo.")
        );

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        bySeverity.put("CRITICAL", 1);
        bySeverity.put("HIGH", 2);
        bySeverity.put("MEDIUM", 1);
        bySeverity.put("LOW", 1);
        ReportContent legacy = base.content();
        Metadata metadata = legacy.metadata();
        Summary summary = new Summary(new BigDecimal("16.67"), new BigDecimal("12.50"), 6, 1, 5, 0, 5, bySeverity, 0);
        ReportContent content = new ReportContent(ReportContent.CURRENT_SCHEMA_VERSION, metadata, summary,
                legacy.categoryCoverage(), legacy.policyResults(), findings, rules,
                ReportGeneratorService.frameworkCoverage(legacy.policyResults(), findings),
                ReportGeneratorService.recommendations(legacy.policyResults(), findings));
        return new ReportDocument(base.reportId(), base.status(), base.checksum(), base.generatedAt(), content);
    }

    private static FindingEntry sarifFinding(UUID ruleId, UUID policyId, String policyName, String severity,
                                             String category, String cweId, String path, Integer line,
                                             String snippet, String suggestedAction) {
        return new FindingEntry(UUID.nameUUIDFromBytes((path + line).getBytes()), policyId, policyName, ruleId,
                severity, category, cweId, path, line, snippet, suggestedAction, null);
    }

    private static PolicyEntry policy(String name, String category, String status, int findings) {
        return new PolicyEntry(UUID.randomUUID(), name, category, "OWASP_TOP_10_2021", "A03:2021", 50, status,
                findings, Math.min(findings, 1), Math.max(findings - 1, 0));
    }

    private static FindingEntry finding(String severity, String category, String path, int line, String snippet) {
        return new FindingEntry(UUID.randomUUID(), UUID.randomUUID(), "Política " + category, UUID.randomUUID(),
                severity, category, "CWE-89", path, line, snippet,
                "Mover el secreto a un gestor de secretos y rotarlo.", null);
    }
}
