package co.icesi.pdgseg.export.sarif;

import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Metadata;
import co.icesi.pdgseg.dto.report.ReportContent.RuleEntry;
import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.export.ReportExporter;
import co.icesi.pdgseg.export.ReportTextSanitizer;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Renders a report as SARIF 2.1.0 so CI/CD platforms (GitHub Code Scanning,
 * Azure DevOps, GitLab...) can show its findings as code annotations. The
 * domain-to-SARIF mapping is documented in segsoft-docs/sarif-mapping.md.
 *
 * Every document is validated against the official schema before its bytes
 * are returned; an invalid one raises SarifValidationException (HTTP 500)
 * and is never served.
 */
@Component
public class SarifReportExporter implements ReportExporter {

    public static final MediaType SARIF_MEDIA_TYPE = new MediaType("application", "sarif+json");
    static final String FORMAT = "sarif";
    static final String TOOL_NAME = "PDG-SegSoft";
    static final String SARIF_VERSION = "2.1.0";
    static final String SARIF_SCHEMA_URI =
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
    /** Base id the result paths are relative to: the root of the analyzed repository. */
    static final String SOURCE_ROOT = "%SRCROOT%";
    /** GitHub groups uploads by the automation id up to its last '/'. */
    static final String AUTOMATION_CATEGORY = "pdg-segsoft/";

    private static final Map<String, String> LEVELS = Map.of(
            "CRITICAL", "error", "HIGH", "error", "MEDIUM", "warning", "LOW", "note");

    /** GitHub's security-severity scale: >=9 critical, 7-8.9 high, 4-6.9 medium, <4 low. */
    private static final Map<String, String> SECURITY_SEVERITY = Map.of(
            "CRITICAL", "9.5", "HIGH", "8.0", "MEDIUM", "5.5", "LOW", "2.0");

    private static final Map<String, String> CATEGORY_TAGS = Map.of(
            "SQL_INJECTION", "sql-injection",
            "XSS", "xss",
            "AUTHENTICATION_FAILURE", "authentication-failure",
            "INSECURE_DATA_HANDLING", "insecure-data-handling",
            "DEPENDENCY_VULNERABILITY", "dependency-vulnerability");

    /** Fallback help page per category when a rule has no CWE (OWASP Top 10 2021). */
    private static final Map<String, String> CATEGORY_HELP = Map.of(
            "SQL_INJECTION", "https://owasp.org/Top10/A03_2021-Injection/",
            "XSS", "https://owasp.org/Top10/A03_2021-Injection/",
            "AUTHENTICATION_FAILURE", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "INSECURE_DATA_HANDLING", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "DEPENDENCY_VULNERABILITY", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/");

    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");
    private static final Pattern CWE_ID = Pattern.compile("(?i)^CWE-(\\d+)$");
    private static final Pattern SEMVER = Pattern.compile("^\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?$");
    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\x00-\\x1F\\x7F]");
    private static final Pattern DRIVE_LETTER = Pattern.compile("^[A-Za-z]:/");

    private final ReportTextSanitizer sanitizer;
    private final SarifSchemaValidator validator;
    private final String toolVersion;
    private final String informationUri;
    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public SarifReportExporter(
            ReportTextSanitizer sanitizer,
            SarifSchemaValidator validator,
            @Value("${report.sarif.tool-version:0.1.0}") String toolVersion,
            @Value("${report.sarif.information-uri:https://github.com/JEGH18/segsoft-backend}") String informationUri
    ) {
        this.sanitizer = sanitizer;
        this.validator = validator;
        // An unfiltered "@project.version@" (IDE run without Maven) is not a version.
        this.toolVersion = toolVersion == null || toolVersion.isBlank() || toolVersion.contains("@")
                ? "0.0.0-dev" : toolVersion.trim();
        this.informationUri = informationUri;
    }

    @Override
    public String format() {
        return FORMAT;
    }

    @Override
    public MediaType mediaType() {
        return SARIF_MEDIA_TYPE;
    }

    @Override
    public String fileExtension() {
        return FORMAT;
    }

    @Override
    public byte[] export(ReportDocument report) {
        String json;
        try {
            json = mapper.writeValueAsString(buildSarif(report));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("No se pudo serializar el reporte SARIF", e);
        }
        validator.validate(json);
        return json.getBytes(StandardCharsets.UTF_8);
    }

    // ---- Document --------------------------------------------------------------------

    ObjectNode buildSarif(ReportDocument report) {
        ReportContent content = report.content();
        Map<String, RuleInfo> rules = collectRules(content);
        List<String> ruleIds = new ArrayList<>(rules.keySet());

        ObjectNode sarif = JsonNodeFactory.instance.objectNode();
        sarif.put("$schema", SARIF_SCHEMA_URI);
        sarif.put("version", SARIF_VERSION);
        ObjectNode run = sarif.putArray("runs").addObject();

        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", TOOL_NAME);
        driver.put("version", toolVersion);
        if (SEMVER.matcher(toolVersion).matches()) {
            driver.put("semanticVersion", toolVersion);
        }
        driver.put("informationUri", informationUri);
        driver.put("organization", "Universidad Icesi");
        ArrayNode descriptors = driver.putArray("rules");
        rules.values().forEach(rule -> addRuleDescriptor(descriptors, rule));

        run.putObject("automationDetails").put("id", AUTOMATION_CATEGORY + report.reportId());
        addVersionControlProvenance(run, content.metadata());
        addInvocation(run, content);

        ArrayNode results = run.putArray("results");
        for (FindingEntry finding : sortedFindings(content.findings())) {
            String ruleId = ruleKey(finding);
            addResult(results, finding, rules.get(ruleId), ruleIds.indexOf(ruleId));
        }

        addRunProperties(run, report);
        return sarif;
    }

    // ---- tool.driver.rules -------------------------------------------------------------

    private record RuleInfo(String id, UUID policyId, String policyName, String type, String severity,
                            String category, String cweId, String description) {
    }

    /**
     * The executed rules frozen in the report, plus any rule a finding points
     * to that is not among them (schema-v1 reports carry no rule list, and a
     * deleted rule leaves its findings without one), so every result's ruleId
     * resolves to a descriptor.
     */
    private Map<String, RuleInfo> collectRules(ReportContent content) {
        Map<String, RuleInfo> rules = new LinkedHashMap<>();
        if (content.rules() != null) {
            for (RuleEntry rule : content.rules()) {
                rules.putIfAbsent(rule.ruleId().toString(), new RuleInfo(rule.ruleId().toString(), rule.policyId(),
                        rule.policyName(), rule.type(), rule.severity(), rule.category(), rule.cweId(),
                        rule.description()));
            }
        }
        for (FindingEntry finding : sortedFindings(content.findings())) {
            rules.putIfAbsent(ruleKey(finding), new RuleInfo(ruleKey(finding), finding.policyId(),
                    finding.policyName(), null, finding.severity(), finding.category(), finding.cweId(), null));
        }
        return rules;
    }

    private void addRuleDescriptor(ArrayNode descriptors, RuleInfo rule) {
        ObjectNode descriptor = descriptors.addObject();
        descriptor.put("id", rule.id());
        descriptor.put("name", ruleName(rule));
        descriptor.putObject("shortDescription").put("text", shortDescription(rule));
        descriptor.putObject("fullDescription").put("text", fullDescription(rule));
        descriptor.put("helpUri", helpUri(rule));
        descriptor.putObject("defaultConfiguration").put("level", level(rule.severity()));

        ObjectNode properties = descriptor.putObject("properties");
        ArrayNode tags = properties.putArray("tags");
        tags.add("security");
        String categoryTag = CATEGORY_TAGS.get(rule.category());
        if (categoryTag != null) {
            tags.add(categoryTag);
        }
        String cweNumber = cweNumber(rule.cweId());
        if (cweNumber != null) {
            tags.add("external/cwe/cwe-" + cweNumber);
        }
        properties.put("security-severity", SECURITY_SEVERITY.getOrDefault(rule.severity(), "5.5"));
        putIfPresent(properties, "severity", rule.severity());
        putIfPresent(properties, "category", rule.category());
        putIfPresent(properties, "ruleType", rule.type());
        putIfPresent(properties, "policyId", rule.policyId());
        putIfPresent(properties, "policyName", sanitizer.field(rule.policyName()));
    }

    private String shortDescription(RuleInfo rule) {
        String description = sanitizer.field(rule.description());
        if (!description.isEmpty()) {
            return description;
        }
        String policy = sanitizer.field(rule.policyName());
        return policy.isEmpty() ? "Regla de seguridad de SegSoft" : policy;
    }

    private String fullDescription(RuleInfo rule) {
        StringBuilder text = new StringBuilder(shortDescription(rule)).append('.');
        String policy = sanitizer.field(rule.policyName());
        if (!policy.isEmpty()) {
            text.append(" Política: «").append(policy).append("».");
        }
        if (rule.category() != null) {
            text.append(" Categoría: ").append(rule.category()).append('.');
        }
        if (rule.cweId() != null && !rule.cweId().isBlank()) {
            text.append(' ').append(sanitizer.field(rule.cweId())).append('.');
        }
        return text.toString();
    }

    /** Non-localizable PascalCase identifier derived from the description. */
    private String ruleName(RuleInfo rule) {
        String source = rule.description() != null && !rule.description().isBlank()
                ? rule.description()
                : (rule.category() != null ? rule.category() : "Segsoft") + " " + (rule.type() != null ? rule.type() : "Rule");
        String ascii = Normalizer.normalize(source, Normalizer.Form.NFD).replaceAll("\\p{M}", "");
        StringBuilder name = new StringBuilder();
        for (String word : ascii.split("[^A-Za-z0-9]+")) {
            if (!word.isEmpty()) {
                name.append(Character.toUpperCase(word.charAt(0))).append(word.substring(1).toLowerCase(Locale.ROOT));
            }
        }
        if (name.isEmpty()) {
            return "SegsoftRule";
        }
        return name.length() > 80 ? name.substring(0, 80) : name.toString();
    }

    private String helpUri(RuleInfo rule) {
        String cweNumber = cweNumber(rule.cweId());
        if (cweNumber != null) {
            return "https://cwe.mitre.org/data/definitions/" + cweNumber + ".html";
        }
        return CATEGORY_HELP.getOrDefault(rule.category(), informationUri);
    }

    private static String cweNumber(String cweId) {
        if (cweId == null) {
            return null;
        }
        Matcher matcher = CWE_ID.matcher(cweId.trim());
        return matcher.matches() ? matcher.group(1) : null;
    }

    // ---- results -------------------------------------------------------------------------

    private void addResult(ArrayNode results, FindingEntry finding, RuleInfo rule, int ruleIndex) {
        ObjectNode result = results.addObject();
        result.put("ruleId", rule.id());
        result.put("ruleIndex", ruleIndex);
        result.put("level", level(finding.severity()));
        result.putObject("message").put("text", resultMessage(finding, rule));

        ArrayNode locations = result.putArray("locations");
        String uri = repositoryRelativeUri(finding.filePath());
        if (uri != null) {
            ObjectNode physical = locations.addObject().putObject("physicalLocation");
            ObjectNode artifact = physical.putObject("artifactLocation");
            artifact.put("uri", uri);
            artifact.put("uriBaseId", SOURCE_ROOT);
            if (finding.lineNumber() != null && finding.lineNumber() >= 1) {
                ObjectNode region = physical.putObject("region");
                region.put("startLine", finding.lineNumber());
                String snippet = sanitizer.snippet(finding.evidenceSnippet());
                if (!snippet.isEmpty()) {
                    region.putObject("snippet").put("text", snippet);
                }
            }
        }

        ObjectNode properties = result.putObject("properties");
        putIfPresent(properties, "findingId", finding.findingId());
        putIfPresent(properties, "severity", finding.severity());
        putIfPresent(properties, "category", finding.category());
        putIfPresent(properties, "policyId", finding.policyId());
        putIfPresent(properties, "policyName", sanitizer.field(finding.policyName()));
        putIfPresent(properties, "cweId", sanitizer.field(finding.cweId()));
        putIfPresent(properties, "fileSha256", sanitizer.field(finding.fileSha256()));
    }

    private String resultMessage(FindingEntry finding, RuleInfo rule) {
        StringBuilder text = new StringBuilder(shortDescription(rule)).append('.');
        String policy = sanitizer.field(finding.policyName());
        if (!policy.isEmpty() && !policy.equals(shortDescription(rule))) {
            text.append(" Política incumplida: «").append(policy).append("».");
        }
        String action = sanitizer.text(finding.suggestedAction());
        if (!action.isEmpty()) {
            text.append(" Acción sugerida: ").append(action);
        }
        return text.toString();
    }

    /**
     * Turns a stored file path into a URI reference relative to the root of
     * the analyzed repository (resolved against %SRCROOT%): forward slashes,
     * no leading "./" or "/", no drive letter, every segment percent-encoded.
     * A path that climbs out of the root ("..") cannot be expressed relative
     * to it, so it gets no location rather than a misleading one.
     */
    static String repositoryRelativeUri(String path) {
        if (path == null) {
            return null;
        }
        String normalized = CONTROL_CHARS.matcher(path).replaceAll("").replace('\\', '/').trim();
        normalized = DRIVE_LETTER.matcher(normalized).replaceFirst("");
        List<String> segments = new ArrayList<>();
        for (String segment : normalized.split("/")) {
            if (segment.isEmpty() || segment.equals(".")) {
                continue;
            }
            if (segment.equals("..")) {
                return null;
            }
            segments.add(encodeSegment(segment));
        }
        return segments.isEmpty() ? null : String.join("/", segments);
    }

    /** RFC 3986 path-segment encoding: unreserved and sub-delims stay, the rest is %XX (UTF-8). */
    private static String encodeSegment(String segment) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : segment.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xFF);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || "-._~!$&'()*+,;=:@".indexOf(c) >= 0) {
                encoded.append(c);
            } else {
                encoded.append('%').append(String.format("%02X", b & 0xFF));
            }
        }
        return encoded.toString();
    }

    // ---- run metadata -----------------------------------------------------------------

    /** Only for Git sources, with any credentials stripped from the URL. */
    private void addVersionControlProvenance(ObjectNode run, Metadata metadata) {
        if (!"GIT".equals(metadata.sourceType()) || metadata.gitUrl() == null) {
            return;
        }
        String repositoryUri = withoutUserInfo(metadata.gitUrl());
        if (repositoryUri == null) {
            return;
        }
        ObjectNode provenance = run.putArray("versionControlProvenance").addObject();
        provenance.put("repositoryUri", repositoryUri);
        String branch = sanitizer.field(metadata.branch());
        if (!branch.isEmpty()) {
            provenance.put("branch", branch);
        }
    }

    private static String withoutUserInfo(String url) {
        try {
            URI uri = new URI(url.trim());
            if (!uri.isAbsolute() || uri.getHost() == null) {
                return null;
            }
            return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, null).toString();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private void addInvocation(ObjectNode run, ReportContent content) {
        ObjectNode invocation = run.putArray("invocations").addObject();
        invocation.put("executionSuccessful", true);
        putTimestamp(invocation, "startTimeUtc", content.metadata().analysisStartedAt());
        putTimestamp(invocation, "endTimeUtc", content.metadata().analysisCompletedAt());
        invocation.putObject("properties")
                .put("rulesExecuted", content.metadata().rulesExecuted())
                .put("rulesTotal", content.metadata().rulesTotal())
                .put("ruleExecutionErrors", content.summary().executionErrors());
    }

    private void addRunProperties(ObjectNode run, ReportDocument report) {
        ReportContent content = report.content();
        ObjectNode properties = run.putObject("properties");
        properties.put("reportId", report.reportId().toString());
        properties.put("reportStatus", report.status());
        properties.put("reportChecksum", report.checksum());
        putTimestamp(properties, "reportGeneratedAt", report.generatedAt());
        putIfPresent(properties, "analysisId", content.metadata().analysisId());
        putIfPresent(properties, "repositoryName", sanitizer.field(content.metadata().repositoryName()));
        putIfPresent(properties, "compliancePercentage", content.summary().compliancePercentage());
        putIfPresent(properties, "weightedCompliancePercentage", content.summary().weightedCompliancePercentage());
        properties.put("policiesEvaluated", content.summary().policiesEvaluated());
        properties.put("totalFindings", content.summary().totalFindings());
    }

    // ---- helpers -------------------------------------------------------------------------------

    static String level(String severity) {
        return LEVELS.getOrDefault(severity, "warning");
    }

    private static String ruleKey(FindingEntry finding) {
        if (finding.ruleId() != null) {
            return finding.ruleId().toString();
        }
        return finding.policyId() != null ? "policy-" + finding.policyId() : "segsoft-unclassified";
    }

    private static List<FindingEntry> sortedFindings(List<FindingEntry> findings) {
        if (findings == null) {
            return List.of();
        }
        return findings.stream()
                .sorted(Comparator.comparingInt((FindingEntry f) -> rank(f.severity()))
                        .thenComparing(f -> String.valueOf(f.filePath()))
                        .thenComparing(f -> f.lineNumber() != null ? f.lineNumber() : 0))
                .toList();
    }

    private static int rank(String severity) {
        int index = SEVERITY_ORDER.indexOf(severity);
        return index < 0 ? SEVERITY_ORDER.size() : index;
    }

    private static void putTimestamp(ObjectNode node, String field, OffsetDateTime value) {
        if (value != null) {
            node.put(field, value.toInstant().toString());
        }
    }

    private static void putIfPresent(ObjectNode node, String field, Object value) {
        if (value == null || (value instanceof String text && text.isBlank())) {
            return;
        }
        if (value instanceof java.math.BigDecimal number) {
            node.put(field, number);
        } else {
            node.put(field, value.toString());
        }
    }
}
