package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.FrameworkCoverage;
import co.icesi.pdgseg.dto.report.ReportContent.PolicyEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Recommendation;
import co.icesi.pdgseg.dto.response.AnalysisResponse;
import co.icesi.pdgseg.dto.response.AnalysisResultsResponse;
import co.icesi.pdgseg.dto.response.FindingResponse;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicyResult;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.entity.enums.SourceType;
import co.icesi.pdgseg.repository.PolicyResultRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReportGeneratorServiceTest {

    private static PolicyEntry policy(String name, String category, String framework, String control,
                                      String status, int weight) {
        return new PolicyEntry(UUID.randomUUID(), name, category, framework, control, weight, status, 0, 0, 0);
    }

    private static FindingEntry finding(PolicyEntry policy, String severity, String action) {
        return new FindingEntry(UUID.randomUUID(), policy.policyId(), policy.name(), UUID.randomUUID(), severity,
                policy.category(), null, "src/App.java", 1, "x", action, null);
    }

    // ---- Claude Code Security catalog ------------------------------------------------

    @Test
    void categoryCoverageAlwaysListsTheFiveCatalogCategories() {
        PolicyEntry sql = policy("SQL", "SQL_INJECTION", "OWASP_TOP_10_2021", "A03:2021", "NON_COMPLIANT", 80);
        var coverage = ReportGeneratorService.categoryCoverage(List.of(sql), List.of(finding(sql, "CRITICAL", null)));

        assertThat(coverage).extracting(ReportContent.CategoryCoverage::category).containsExactly(
                "SQL_INJECTION", "XSS", "AUTHENTICATION_FAILURE", "INSECURE_DATA_HANDLING", "DEPENDENCY_VULNERABILITY");
        assertThat(coverage.get(0).nonCompliantPolicies()).isEqualTo(1);
        assertThat(coverage.get(0).highOrCriticalFindings()).isEqualTo(1);
        assertThat(coverage.get(1).policiesEvaluated()).isZero();
    }

    // ---- Frameworks ----------------------------------------------------------------------

    @Test
    void frameworkCoverageGroupsPoliciesByFrameworkInCatalogOrder() {
        PolicyEntry owasp1 = policy("Inyección", "SQL_INJECTION", "OWASP_TOP_10_2021", "A03:2021", "NON_COMPLIANT", 80);
        PolicyEntry owasp2 = policy("XSS", "XSS", "OWASP_TOP_10_2021", "A03:2021", "COMPLIANT", 50);
        PolicyEntry iso = policy("Cifrado", "INSECURE_DATA_HANDLING", "ISO_27001", "A.8.24", "REQUIRES_REVIEW", 60);
        PolicyEntry nist = policy("Logs", "AUTHENTICATION_FAILURE", "NIST_SP_800_53", null, "COMPLIANT", 40);

        List<FrameworkCoverage> coverage = ReportGeneratorService.frameworkCoverage(
                List.of(nist, owasp1, iso, owasp2), List.of(finding(owasp1, "HIGH", null), finding(iso, "LOW", null)));

        assertThat(coverage).extracting(FrameworkCoverage::framework)
                .containsExactly("ISO_27001", "OWASP_TOP_10_2021", "NIST_SP_800_53");
        FrameworkCoverage owasp = coverage.get(1);
        assertThat(owasp.policiesEvaluated()).isEqualTo(2);
        assertThat(owasp.compliantPolicies()).isEqualTo(1);
        assertThat(owasp.nonCompliantPolicies()).isEqualTo(1);
        assertThat(owasp.findings()).isEqualTo(1);
        assertThat(owasp.highOrCriticalFindings()).isEqualTo(1);
        assertThat(coverage.get(2).controls()).isEmpty();
    }

    @Test
    void aControlTakesTheWorstStatusOfThePoliciesThatImplementIt() {
        PolicyEntry failing = policy("Inyección", "SQL_INJECTION", "OWASP_TOP_10_2021", "A03:2021", "NON_COMPLIANT", 80);
        PolicyEntry passing = policy("XSS", "XSS", "OWASP_TOP_10_2021", " A03:2021 ", "COMPLIANT", 50);

        var controls = ReportGeneratorService.frameworkCoverage(List.of(passing, failing), List.of()).get(0).controls();

        assertThat(controls).singleElement().satisfies(control -> {
            assertThat(control.controlId()).isEqualTo("A03:2021");
            assertThat(control.status()).isEqualTo("NON_COMPLIANT");
            assertThat(control.policyIds()).containsExactlyInAnyOrder(failing.policyId(), passing.policyId());
        });
    }

    // ---- Recommendations ---------------------------------------------------------------

    @Test
    void recommendationsCoverNonCompliantPoliciesMostSevereFirst() {
        PolicyEntry medium = policy("Media", "XSS", "OWASP_TOP_10_2021", null, "NON_COMPLIANT", 90);
        PolicyEntry critical = policy("Crítica", "SQL_INJECTION", "OWASP_TOP_10_2021", null, "NON_COMPLIANT", 10);
        PolicyEntry review = policy("Revisión", "AUTHENTICATION_FAILURE", "ISO_27001", null, "REQUIRES_REVIEW", 50);
        PolicyEntry compliant = policy("Cumple", "XSS", "ISO_27001", null, "COMPLIANT", 100);

        List<Recommendation> recommendations = ReportGeneratorService.recommendations(
                List.of(medium, compliant, review, critical),
                List.of(finding(medium, "MEDIUM", "Escapar la salida"), finding(critical, "CRITICAL", "Usar PreparedStatement"),
                        finding(critical, "HIGH", "Usar PreparedStatement"), finding(critical, "HIGH", "Validar entradas")));

        assertThat(recommendations).extracting(Recommendation::policyName).containsExactly("Crítica", "Media", "Revisión");
        assertThat(recommendations).extracting(Recommendation::priority).containsExactly(1, 2, 3);
        Recommendation first = recommendations.get(0);
        assertThat(first.highestSeverity()).isEqualTo("CRITICAL");
        assertThat(first.highOrCriticalFindings()).isEqualTo(3);
        assertThat(first.action()).isEqualTo("Usar PreparedStatement"); // the most repeated suggestion
        assertThat(recommendations.get(2).action()).contains("Revisar manualmente").contains("Revisión");
    }

    @Test
    void recommendationsAreCappedAtTen() {
        List<PolicyEntry> failing = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            failing.add(policy("P" + i, "XSS", "OWASP_TOP_10_2021", null, "NON_COMPLIANT", i));
        }
        assertThat(ReportGeneratorService.recommendations(failing, List.of())).hasSize(10);
    }

    // ---- Full generation -----------------------------------------------------------------

    @Test
    void generateConsolidatesEverySectionFromTheAnalysis() {
        AnalysisService analysisService = mock(AnalysisService.class);
        PolicyResultRepository policyResults = mock(PolicyResultRepository.class);
        RuleRepository rules = mock(RuleRepository.class);
        AnalysisSnapshotService snapshots = mock(AnalysisSnapshotService.class);
        when(snapshots.findSnapshot(any())).thenReturn(Optional.empty());
        ReportGeneratorService generator = new ReportGeneratorService(analysisService, policyResults, rules, snapshots,
                new SecretMaskingService());

        UUID analysisId = UUID.randomUUID();
        Repository repository = new Repository();
        repository.setOriginalName("acme");
        repository.setSourceType(SourceType.GIT);
        repository.setGitUrl("https://ci:s3cr3t@github.com/acme/app.git");
        Analysis analysis = new Analysis();
        analysis.setId(analysisId);
        analysis.setRepository(repository);
        analysis.setStatus(AnalysisStatus.COMPLETED);

        Policy policy = new Policy();
        policy.setId(UUID.randomUUID());
        policy.setName("Consultas parametrizadas");
        policy.setCategory(Category.SQL_INJECTION);
        policy.setFramework(Framework.OWASP_TOP_10_2021);
        policy.setControlId("A03:2021");
        policy.setWeight(80);
        PolicyResult result = new PolicyResult();
        result.setPolicy(policy);
        result.setStatus(PolicyComplianceStatus.NON_COMPLIANT);
        result.setFindingsCount(1);
        result.setHighOrCriticalCount(1);
        result.setLowOrMediumCount(0);
        when(policyResults.findByAnalysisId(analysisId)).thenReturn(List.of(result));
        FindingResponse finding = new FindingResponse(UUID.randomUUID(), policy.getId(), policy.getName(),
                UUID.randomUUID(), SeverityLevel.CRITICAL, "SQL_INJECTION", "src/Dao.java", 10, "password=hunter2",
                null, "CWE-89", "Usar PreparedStatement");
        when(analysisService.getResults(analysisId)).thenReturn(new AnalysisResultsResponse(
                new AnalysisResponse(analysisId, null, AnalysisStatus.COMPLETED, 1, 1, BigDecimal.valueOf(100),
                        null, null, null, null, null),
                List.of(finding), List.of(), List.of(), BigDecimal.ZERO, BigDecimal.ZERO, Map.of()));

        ReportContent content = generator.generate(analysis, "auditor", OffsetDateTime.now());

        assertThat(content.schemaVersion()).isEqualTo(3);
        assertThat(content.metadata().repositoryName()).isEqualTo("acme");
        assertThat(content.metadata().gitUrl()).doesNotContain("s3cr3t");
        assertThat(content.summary().nonCompliantPolicies()).isEqualTo(1);
        assertThat(content.summary().findingsBySeverity()).containsEntry("CRITICAL", 1).containsEntry("LOW", 0);
        assertThat(content.categoryCoverage()).hasSize(5);
        assertThat(content.frameworkCoverage()).singleElement()
                .satisfies(f -> assertThat(f.framework()).isEqualTo("OWASP_TOP_10_2021"));
        assertThat(content.recommendations()).singleElement()
                .satisfies(r -> assertThat(r.action()).isEqualTo("Usar PreparedStatement"));
        assertThat(content.findings()).singleElement()
                .satisfies(f -> assertThat(f.evidenceSnippet()).isEqualTo("password=*****"));
        assertThat(content.rules()).isEmpty();
    }
}
