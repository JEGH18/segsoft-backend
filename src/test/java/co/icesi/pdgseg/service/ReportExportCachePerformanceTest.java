package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.export.ReportExporterRegistry;
import co.icesi.pdgseg.export.ReportFixtures;
import co.icesi.pdgseg.export.ReportTextSanitizer;
import co.icesi.pdgseg.export.cache.ExportFileCache;
import co.icesi.pdgseg.export.cache.ExportSizeLimit;
import co.icesi.pdgseg.export.pdf.PdfReportExporter;
import co.icesi.pdgseg.export.sarif.SarifReportExporter;
import co.icesi.pdgseg.export.sarif.SarifSchemaValidator;
import co.icesi.pdgseg.repository.ReportRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Response time of exports served from the cache (X-Cache: HIT), measured on
 * the real export path -- ReportService with the real PDF/SARIF exporters,
 * schema validation and filesystem cache -- for a large report (500
 * findings). Only the repository is mocked, so the test runs without a
 * database; ReportExportIntegrationTest repeats the measurement over HTTP.
 *
 * Results are printed so they can be recorded in the performance notes.
 */
class ReportExportCachePerformanceTest {

    static final long HIT_BUDGET_MS = 200;
    private static final int WARMUP = 5;
    private static final int SAMPLES = 50;

    @TempDir Path cacheDir;

    @ParameterizedTest
    @ValueSource(strings = {"pdf", "sarif"})
    void cachedExportsAreServedWellUnder200Ms(String format) throws Exception {
        ObjectMapper objectMapper = Jackson2ObjectMapperBuilder.json().build();
        UUID reportId = UUID.randomUUID();
        Report report = largeReport(reportId, objectMapper);
        ReportRepository repository = mock(ReportRepository.class);
        when(repository.findById(reportId)).thenReturn(Optional.of(report));

        ReportTextSanitizer sanitizer = new ReportTextSanitizer(new SecretMaskingService());
        ReportExporterRegistry registry = new ReportExporterRegistry(List.of(
                new PdfReportExporter(sanitizer, "America/Bogota"),
                new SarifReportExporter(sanitizer, new SarifSchemaValidator(), "0.1.0", "https://example.org")));
        ReportService service = new ReportService(repository, null, null, null,
                new StructuredReportMapper(new SecretMaskingService()), registry,
                new ExportFileCache(cacheDir.toString(), Duration.ofHours(1)), new ExportSizeLimit(50),
                mock(AuditService.class), objectMapper);

        long missStart = System.nanoTime();
        ExportedReport miss = service.export(reportId, format, "auditor");
        double missMs = (System.nanoTime() - missStart) / 1e6;
        assertThat(miss.cacheHit()).isFalse();

        for (int i = 0; i < WARMUP; i++) {
            service.export(reportId, format, "auditor");
        }
        double[] hits = new double[SAMPLES];
        for (int i = 0; i < SAMPLES; i++) {
            long start = System.nanoTime();
            ExportedReport hit = service.export(reportId, format, "auditor");
            hits[i] = (System.nanoTime() - start) / 1e6;
            assertThat(hit.cacheHit()).isTrue();
            assertThat(hit.content()).hasSize(miss.content().length);
        }

        Arrays.sort(hits);
        double p50 = hits[SAMPLES / 2];
        double p95 = hits[(int) Math.ceil(SAMPLES * 0.95) - 1];
        double max = hits[SAMPLES - 1];
        System.out.printf("[export-cache] format=%s size=%dKB MISS=%.1fms HIT p50=%.2fms p95=%.2fms max=%.2fms (n=%d)%n",
                format, miss.content().length / 1024, missMs, p50, p95, max, SAMPLES);

        assertThat(p95).as("p95 de exportaciones HIT (%s)", format).isLessThan(HIT_BUDGET_MS);
        assertThat(max).as("peor exportación HIT (%s)", format).isLessThan(HIT_BUDGET_MS);
    }

    /** The SARIF fixture with its findings replicated to 500, so rendering is non-trivial. */
    static Report largeReport(UUID reportId, ObjectMapper objectMapper) throws Exception {
        ReportContent base = ReportFixtures.documentForSarif().content();
        List<FindingEntry> findings = new ArrayList<>();
        for (int i = 0; findings.size() < 500; i++) {
            FindingEntry f = base.findings().get(i % base.findings().size());
            findings.add(new FindingEntry(UUID.randomUUID(), f.policyId(), f.policyName(), f.ruleId(), f.severity(),
                    f.category(), f.cweId(), f.filePath(), f.lineNumber() != null ? f.lineNumber() + i : null,
                    f.evidenceSnippet(), f.suggestedAction(), f.fileSha256()));
        }
        ReportContent content = new ReportContent(base.schemaVersion(), base.metadata(), base.summary(),
                base.categoryCoverage(), base.policyResults(), findings, base.rules(), base.frameworkCoverage(),
                base.recommendations());
        String json = objectMapper.writeValueAsString(content);

        Report report = new Report();
        report.setId(reportId);
        report.setStatus(ReportStatus.GENERATED);
        report.setContent(json);
        report.setChecksum(ReportChecksum.of(json));
        report.setGeneratedAt(OffsetDateTime.now());
        return report;
    }
}
