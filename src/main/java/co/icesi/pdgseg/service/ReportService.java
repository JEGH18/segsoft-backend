package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.report.ExportedReport;
import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.Metadata;
import co.icesi.pdgseg.dto.report.ReportContent.Summary;
import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.dto.response.ReportResponse;
import co.icesi.pdgseg.dto.response.ReportSummaryResponse;
import co.icesi.pdgseg.dto.response.StructuredReportResponse;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Report;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.ReportStatus;
import co.icesi.pdgseg.exception.ReportIntegrityException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.export.ReportExporter;
import co.icesi.pdgseg.export.ReportExporterRegistry;
import co.icesi.pdgseg.export.cache.ExportFileCache;
import co.icesi.pdgseg.export.cache.ExportSizeLimit;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.ReportRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Lifecycle of compliance reports: generation (append-only), retrieval with
 * integrity verification, history and export. Content consolidation lives in
 * {@link ReportGeneratorService}; the API projection in {@link StructuredReportMapper}.
 */
@Service
public class ReportService {

    static final String NOT_COMPLETED_MESSAGE = "Solo se pueden generar reportes de análisis completados";

    private final ReportRepository reportRepository;
    private final AnalysisRepository analysisRepository;
    private final UserRepository userRepository;
    private final ReportGeneratorService reportGenerator;
    private final StructuredReportMapper structuredReportMapper;
    private final ReportExporterRegistry exporterRegistry;
    private final ExportFileCache exportCache;
    private final ExportSizeLimit exportSizeLimit;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public ReportService(
            ReportRepository reportRepository,
            AnalysisRepository analysisRepository,
            UserRepository userRepository,
            ReportGeneratorService reportGenerator,
            StructuredReportMapper structuredReportMapper,
            ReportExporterRegistry exporterRegistry,
            ExportFileCache exportCache,
            ExportSizeLimit exportSizeLimit,
            AuditService auditService,
            ObjectMapper objectMapper
    ) {
        this.reportRepository = reportRepository;
        this.analysisRepository = analysisRepository;
        this.userRepository = userRepository;
        this.reportGenerator = reportGenerator;
        this.structuredReportMapper = structuredReportMapper;
        this.exporterRegistry = exporterRegistry;
        this.exportCache = exportCache;
        this.exportSizeLimit = exportSizeLimit;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
    }

    /**
     * Freezes the results of a COMPLETED analysis into a new, append-only
     * report. Any other status is rejected (422) naming the current one.
     */
    @Transactional
    public ReportResponse generate(UUID analysisId, String username) {
        Analysis analysis = analysisRepository.findById(analysisId)
                .orElseThrow(() -> new ResourceNotFoundException("Análisis no encontrado"));
        if (analysis.getStatus() != AnalysisStatus.COMPLETED) {
            throw new UnprocessableEntityException(
                    NOT_COMPLETED_MESSAGE + " (estado actual: " + analysis.getStatus() + ")");
        }

        OffsetDateTime generatedAt = OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS);
        String content = serialize(reportGenerator.generate(analysis, username, generatedAt));

        Report report = new Report();
        report.setAnalysis(analysis);
        report.setStatus(ReportStatus.GENERATED);
        report.setContent(content);
        report.setChecksum(ReportChecksum.of(content));
        report.setGeneratedBy(userRepository.findByUsername(username).orElse(null));
        report.setGeneratedAt(generatedAt);
        report = reportRepository.save(report);

        auditService.record("REPORT_GENERATED", username, null,
                Map.of("reportId", report.getId().toString(), "analysisId", analysisId.toString()));
        return new ReportResponse(report.getId(), analysisId, report.getStatus(), report.getChecksum(),
                report.getGeneratedAt());
    }

    /**
     * The structured report, after recomputing its checksum: content that no
     * longer matches it (manipulated in the database) is refused with 409
     * instead of being presented as a valid report.
     *
     * Not transactional, so the integrity-violation audit entry is committed.
     */
    public StructuredReportResponse get(UUID reportId, ReportView view, String username) {
        Report report = loadVerified(reportId, username);
        return structuredReportMapper.toResponse(report, parse(report), view, exporterRegistry.supportedFormats());
    }

    /**
     * Order of checks: unsupported format (400, without touching the
     * database), unknown report (404), integrity (409), then the export
     * cache, then the size limit (422). Integrity is verified on every
     * request, cache hit or not, so a tampered report never yields a file.
     *
     * The cache key embeds the verified checksum, so a report whose content
     * changes never matches an older export. A file above MAX_EXPORT_SIZE_MB
     * is rejected before it is cached; a cached one is checked again in case
     * the limit was lowered after it was stored.
     *
     * Deliberately not transactional: the integrity-violation audit entry must
     * be committed even though the call ends in an exception.
     */
    public ExportedReport export(UUID reportId, String format, String username) {
        ReportExporter exporter = exporterRegistry.resolve(format);
        Report report = loadVerified(reportId, username);

        String key = ExportFileCache.key(reportId, exporter.format(), report.getChecksum());
        ExportFileCache.Lookup lookup = exportCache.getOrCreate(key, () -> {
            byte[] bytes = exporter.export(toDocument(report));
            exportSizeLimit.check(bytes.length);
            return bytes;
        });
        exportSizeLimit.check(lookup.content().length);

        auditService.record("REPORT_EXPORTED", username, null, Map.of(
                "reportId", reportId.toString(),
                "format", exporter.format(),
                "cache", lookup.hit() ? "HIT" : "MISS"));
        return new ExportedReport(lookup.content(), exporter.mediaType(),
                "segsoft-report-" + reportId + "." + exporter.fileExtension(), lookup.hit());
    }

    /** History, newest first: by repository, by analysis or all. Each row says whether it verifies. */
    public Page<ReportSummaryResponse> list(UUID repositoryId, UUID analysisId, Pageable pageable) {
        Page<Report> reports;
        if (repositoryId != null) {
            reports = reportRepository.findByRepositoryId(repositoryId.toString(), pageable);
        } else if (analysisId != null) {
            reports = reportRepository.findByAnalysisIdOrderByGeneratedAtDesc(analysisId, pageable);
        } else {
            reports = reportRepository.findAllByOrderByGeneratedAtDesc(pageable);
        }
        return reports.map(this::toSummary);
    }

    private ReportSummaryResponse toSummary(Report report) {
        boolean integrityVerified = checksumMatches(report);
        ReportContent content = null;
        try {
            content = objectMapper.readValue(report.getContent(), ReportContent.class);
        } catch (JsonProcessingException e) {
            // Unreadable content: the history still lists the report, without its figures.
        }
        Summary summary = content != null ? content.summary() : null;
        Metadata metadata = content != null ? content.metadata() : null;
        return new ReportSummaryResponse(
                report.getId(),
                metadata != null ? metadata.analysisId() : null,
                report.getStatus(),
                report.getChecksum(),
                report.getGeneratedAt(),
                metadata != null ? metadata.generatedBy() : null,
                metadata != null ? metadata.repositoryName() : null,
                summary != null ? summary.compliancePercentage() : null,
                summary != null ? summary.weightedCompliancePercentage() : null,
                summary != null ? summary.policiesEvaluated() : null,
                summary != null ? summary.totalFindings() : null,
                summary != null ? summary.findingsBySeverity() : null,
                integrityVerified,
                exporterRegistry.supportedFormats()
        );
    }

    private Report loadVerified(UUID reportId, String username) {
        Report report = reportRepository.findById(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("Reporte no encontrado"));
        if (!checksumMatches(report)) {
            auditService.record("REPORT_INTEGRITY_VIOLATION", username, null,
                    Map.of("reportId", reportId.toString()));
            throw new ReportIntegrityException(
                    "El checksum almacenado del reporte no coincide con su contenido: el reporte fue alterado");
        }
        return report;
    }

    private static boolean checksumMatches(Report report) {
        byte[] expected = report.getChecksum() == null
                ? new byte[0]
                : report.getChecksum().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII);
        String actualChecksum;
        try {
            actualChecksum = ReportChecksum.of(report.getContent());
        } catch (IllegalArgumentException e) {
            return false;
        }
        return MessageDigest.isEqual(expected, actualChecksum.getBytes(StandardCharsets.US_ASCII));
    }

    private ReportContent parse(Report report) {
        try {
            return objectMapper.readValue(report.getContent(), ReportContent.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Contenido del reporte ilegible", e);
        }
    }

    private ReportDocument toDocument(Report report) {
        return new ReportDocument(report.getId(), report.getStatus().name(), report.getChecksum(),
                report.getGeneratedAt(), parse(report));
    }

    private String serialize(ReportContent content) {
        try {
            return objectMapper.writeValueAsString(content);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("No se pudo serializar el reporte", e);
        }
    }
}
