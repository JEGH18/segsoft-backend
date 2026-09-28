package co.icesi.pdgseg.export.pdf;

import co.icesi.pdgseg.dto.report.ReportContent;
import co.icesi.pdgseg.dto.report.ReportContent.CategoryCoverage;
import co.icesi.pdgseg.dto.report.ReportContent.FindingEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Metadata;
import co.icesi.pdgseg.dto.report.ReportContent.PolicyEntry;
import co.icesi.pdgseg.dto.report.ReportContent.Summary;
import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.export.ReportExporter;
import co.icesi.pdgseg.export.ReportTextSanitizer;
import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.lowagie.text.pdf.draw.DottedLineSeparator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static co.icesi.pdgseg.export.pdf.PdfReportTheme.*;

/**
 * Renders a report following the template in segsoft-docs/reporte-pdf-plantilla.md:
 * cover with metadata, table of contents, executive summary, coverage of the
 * five catalog categories, per-policy results and findings ordered by
 * severity; every page carries its number and the report checksum.
 *
 * Rendering runs twice: the first pass learns which page each section lands
 * on and the total page count, the second pass prints them in the table of
 * contents and the footer. The table of contents has a fixed size, so the
 * layout -- and therefore those numbers -- is identical in both passes.
 */
@Component
public class PdfReportExporter implements ReportExporter {

    static final String FORMAT = "pdf";

    record Section(String key, String title) {
    }

    static final Section EXECUTIVE_SUMMARY = new Section("resumen-ejecutivo", "1. Resumen ejecutivo");
    static final Section CATEGORY_COVERAGE = new Section("cobertura-categorias", "2. Cobertura por categoría");
    static final Section POLICY_RESULTS = new Section("resultados-politica", "3. Resultados por política");
    static final Section FINDINGS = new Section("hallazgos", "4. Hallazgos detallados");
    static final List<Section> SECTIONS = List.of(EXECUTIVE_SUMMARY, CATEGORY_COVERAGE, POLICY_RESULTS, FINDINGS);

    private static final Locale ES_CO = Locale.forLanguageTag("es-CO");
    private static final List<String> CATALOG_CATEGORIES = List.of(
            "SQL_INJECTION", "XSS", "AUTHENTICATION_FAILURE", "INSECURE_DATA_HANDLING", "DEPENDENCY_VULNERABILITY");
    private static final List<String> STATUS_ORDER = List.of("NON_COMPLIANT", "REQUIRES_REVIEW", "COMPLIANT");
    private static final Charset WIN_ANSI = Charset.forName("windows-1252");

    private final ReportTextSanitizer sanitizer;
    private final DateTimeFormatter dateFormat;

    public PdfReportExporter(
            ReportTextSanitizer sanitizer,
            @Value("${report.pdf.time-zone:America/Bogota}") String timeZone
    ) {
        this.sanitizer = sanitizer;
        this.dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z", ES_CO).withZone(ZoneId.of(timeZone));
    }

    @Override
    public String format() {
        return FORMAT;
    }

    @Override
    public MediaType mediaType() {
        return MediaType.APPLICATION_PDF;
    }

    @Override
    public String fileExtension() {
        return FORMAT;
    }

    @Override
    public byte[] export(ReportDocument report) {
        Rendered draft = render(report, Map.of(), 0);
        return render(report, draft.sectionPages(), draft.totalPages()).bytes();
    }

    private record Rendered(byte[] bytes, Map<String, Integer> sectionPages, int totalPages) {
    }

    private Rendered render(ReportDocument report, Map<String, Integer> tocPages, int totalPages) {
        ReportContent content = report.content();
        String repositoryName = sanitizer.field(content.metadata().repositoryName());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, MARGIN_SIDE, MARGIN_SIDE, MARGIN_TOP, MARGIN_BOTTOM);
        try {
            PdfWriter writer = PdfWriter.getInstance(document, out);
            writer.setViewerPreferences(PdfWriter.DisplayDocTitle);
            PdfPageDecorator decorator = new PdfPageDecorator(
                    pdfText(repositoryName),
                    pdfText("Reporte " + report.reportId() + " · Confidencial"),
                    pdfText(report.checksum()),
                    totalPages);
            writer.setPageEvent(decorator);

            document.addTitle(pdfText("Reporte de cumplimiento - " + repositoryName));
            document.addSubject("Reporte de cumplimiento de políticas de seguridad");
            document.addAuthor("SegSoft");
            document.addCreator("SegSoft - PdfReportExporter");
            document.addKeywords("reportId=" + report.reportId() + " sha256=" + pdfText(report.checksum()));
            document.open();

            addCover(document, report, repositoryName);
            document.newPage();
            addTableOfContents(document, tocPages);
            document.newPage();
            addExecutiveSummary(document, content, repositoryName);
            addCategoryCoverage(document, content.categoryCoverage());
            document.newPage();
            addPolicyResults(document, content.policyResults());
            document.newPage();
            addFindings(document, writer, content.findings());

            int pageCount = writer.getPageNumber();
            document.close();
            return new Rendered(out.toByteArray(), Map.copyOf(decorator.sectionPages()), pageCount);
        } catch (DocumentException e) {
            throw new IllegalStateException("No se pudo generar el PDF del reporte", e);
        }
    }

    // ---- Cover --------------------------------------------------------------

    private void addCover(Document document, ReportDocument report, String repositoryName) throws DocumentException {
        Metadata metadata = report.content().metadata();

        Paragraph kicker = new Paragraph("SEGSOFT · UNIVERSIDAD ICESI", COVER_KICKER);
        kicker.setSpacingBefore(70);
        document.add(kicker);

        Paragraph title = new Paragraph("Reporte de cumplimiento de políticas de seguridad", COVER_TITLE);
        title.setLeading(31);
        title.setSpacingBefore(10);
        document.add(title);

        Paragraph subtitle = new Paragraph(pdfText(repositoryName), COVER_SUBTITLE);
        subtitle.setSpacingBefore(10);
        subtitle.setSpacingAfter(34);
        document.add(subtitle);

        PdfPTable table = new PdfPTable(new float[]{0.34f, 0.66f});
        table.setWidthPercentage(100);
        addMetadataRow(table, "Identificador del reporte", report.reportId().toString(), true);
        addMetadataRow(table, "Estado", "GENERATED".equals(report.status()) ? "Generado" : report.status(), false);
        addMetadataRow(table, "Repositorio", repositoryName, false);
        addMetadataRow(table, "Origen", describeSource(metadata), false);
        if (metadata.repositorySha256() != null) {
            addMetadataRow(table, "SHA-256 del archivo", sanitizer.field(metadata.repositorySha256()), true);
        }
        addMetadataRow(table, "Análisis", String.valueOf(metadata.analysisId()), true);
        addMetadataRow(table, "Ejecución del análisis",
                date(metadata.analysisStartedAt()) + "  –  " + date(metadata.analysisCompletedAt()), false);
        addMetadataRow(table, "Reglas ejecutadas", metadata.rulesExecuted() + " de " + metadata.rulesTotal(), false);
        addMetadataRow(table, "Generado por", sanitizer.field(metadata.generatedBy()), false);
        addMetadataRow(table, "Fecha de generación", date(report.generatedAt()), false);
        addMetadataRow(table, "Checksum SHA-256", report.checksum(), true);
        document.add(table);

        PdfPTable notice = new PdfPTable(1);
        notice.setWidthPercentage(100);
        notice.setSpacingBefore(26);
        PdfPCell cell = new PdfPCell();
        cell.setUseVariableBorders(true);
        cell.setBorder(Rectangle.LEFT);
        cell.setBorderWidthLeft(3);
        cell.setBorderColorLeft(ACCENT);
        cell.setBackgroundColor(ZEBRA);
        cell.setPadding(10);
        cell.addElement(new Paragraph("Documento confidencial", BODY_BOLD));
        Paragraph noticeText = new Paragraph(
                "Este reporte contiene resultados de seguridad del repositorio analizado y está dirigido a "
                        + "responsables de seguridad, auditoría y dirección. Los secretos detectados se muestran "
                        + "enmascarados (*****). La integridad del contenido puede verificarse con el checksum "
                        + "SHA-256 impreso en el pie de cada página.", SMALL);
        noticeText.setSpacingBefore(3);
        cell.addElement(noticeText);
        notice.addCell(cell);
        document.add(notice);
    }

    private String describeSource(Metadata metadata) {
        if ("GIT".equals(metadata.sourceType())) {
            String url = sanitizer.field(metadata.gitUrl());
            String branch = sanitizer.field(metadata.branch());
            return "Git: " + url + (branch.isEmpty() ? "" : " (rama " + branch + ")");
        }
        if ("ZIP".equals(metadata.sourceType())) {
            return "Archivo ZIP";
        }
        return sanitizer.field(metadata.sourceType());
    }

    private void addMetadataRow(PdfPTable table, String label, String value, boolean monospace) {
        PdfPCell labelCell = cell(new Phrase(label, SMALL_BOLD), ZEBRA);
        PdfPCell valueCell = cell(new Phrase(pdfText(orDash(value)), monospace ? MONO : TABLE_CELL), WHITE);
        labelCell.setPadding(6);
        valueCell.setPadding(6);
        table.addCell(labelCell);
        table.addCell(valueCell);
    }

    // ---- Table of contents ----------------------------------------------------

    private void addTableOfContents(Document document, Map<String, Integer> tocPages) throws DocumentException {
        Paragraph heading = new Paragraph("Índice", H1);
        heading.setSpacingAfter(18);
        document.add(heading);

        for (Section section : SECTIONS) {
            Paragraph entry = new Paragraph();
            entry.setSpacingAfter(9);
            Chunk title = new Chunk(section.title(), TOC_ENTRY);
            title.setLocalGoto(section.key());
            entry.add(title);
            entry.add(new Chunk(new DottedLineSeparator()));
            Integer page = tocPages.get(section.key());
            Chunk pageNumber = new Chunk(page != null ? page.toString() : "", TOC_ENTRY);
            pageNumber.setLocalGoto(section.key());
            entry.add(pageNumber);
            document.add(entry);
        }

        Paragraph note = new Paragraph(
                "Cada página incluye su número y el checksum SHA-256 del reporte. Si el checksum no coincide con "
                        + "el registrado en SegSoft, el documento no debe considerarse evidencia válida.", SMALL);
        note.setSpacingBefore(24);
        document.add(note);
    }

    private void addSectionHeading(Document document, Section section) throws DocumentException {
        Chunk chunk = new Chunk(section.title(), H1);
        chunk.setLocalDestination(section.key());
        chunk.setGenericTag(section.key());
        Paragraph heading = new Paragraph(chunk);
        heading.setSpacingAfter(10);
        document.add(heading);
    }

    // ---- 1. Executive summary ---------------------------------------------------

    private void addExecutiveSummary(Document document, ReportContent content, String repositoryName)
            throws DocumentException {
        addSectionHeading(document, EXECUTIVE_SUMMARY);
        Summary summary = content.summary();
        int highOrCritical = severityCount(summary, "CRITICAL") + severityCount(summary, "HIGH");

        StringBuilder narrative = new StringBuilder()
                .append("El análisis del repositorio «").append(repositoryName).append("» evaluó ")
                .append(plural(summary.policiesEvaluated(), "política", "políticas")).append(" de seguridad mediante ")
                .append(plural(content.metadata().rulesExecuted(), "regla", "reglas")).append(". Del total, ")
                .append(summary.compliantPolicies()).append(summary.compliantPolicies() == 1 ? " cumple, " : " cumplen, ")
                .append(summary.nonCompliantPolicies())
                .append(summary.nonCompliantPolicies() == 1 ? " no cumple y " : " no cumplen y ")
                .append(summary.requiresReviewPolicies())
                .append(summary.requiresReviewPolicies() == 1 ? " requiere revisión" : " requieren revisión")
                .append(", para un cumplimiento de ").append(percent(summary.compliancePercentage())).append(" (")
                .append(percent(summary.weightedCompliancePercentage())).append(" ponderado por criticidad). ")
                .append("Se identificaron ").append(plural(summary.totalFindings(), "hallazgo", "hallazgos"))
                .append(", ").append(highOrCritical).append(" de severidad alta o crítica.");
        if (summary.executionErrors() > 0) {
            narrative.append(" Durante la ejecución se ")
                    .append(summary.executionErrors() == 1 ? "registró " : "registraron ")
                    .append(plural(summary.executionErrors(), "error de regla", "errores de reglas"))
                    .append("; los resultados de las políticas afectadas pueden estar incompletos.");
        }
        Paragraph intro = new Paragraph(pdfText(narrative.toString()), BODY);
        intro.setLeading(14);
        intro.setSpacingAfter(14);
        document.add(intro);

        PdfPTable kpis = new PdfPTable(4);
        kpis.setWidthPercentage(100);
        kpis.setSpacingAfter(16);
        double compliance = toDouble(summary.compliancePercentage());
        double weighted = toDouble(summary.weightedCompliancePercentage());
        kpis.addCell(kpiCell(percent(summary.compliancePercentage()), "Cumplimiento de políticas",
                complianceColor(compliance)));
        kpis.addCell(kpiCell(percent(summary.weightedCompliancePercentage()), "Cumplimiento ponderado",
                complianceColor(weighted)));
        kpis.addCell(kpiCell(String.valueOf(summary.policiesEvaluated()), "Políticas evaluadas", PRIMARY));
        kpis.addCell(kpiCell(String.valueOf(summary.totalFindings()), "Hallazgos",
                highOrCritical > 0 ? NON_COMPLIANT : PRIMARY));
        document.add(kpis);

        document.add(subheading("Hallazgos por severidad"));
        PdfPTable severities = new PdfPTable(4);
        severities.setWidthPercentage(100);
        severities.setSpacingAfter(16);
        for (String severity : SEVERITY_ORDER) {
            PdfPCell header = cell(new Phrase(severityLabel(severity),
                    withColor(TABLE_HEADER, severityTextOnFill(severity))), severityFill(severity));
            header.setHorizontalAlignment(Element.ALIGN_CENTER);
            severities.addCell(header);
        }
        for (String severity : SEVERITY_ORDER) {
            PdfPCell value = cell(new Phrase(String.valueOf(severityCount(summary, severity)), H2), WHITE);
            value.setHorizontalAlignment(Element.ALIGN_CENTER);
            value.setPadding(7);
            severities.addCell(value);
        }
        document.add(severities);

        document.add(subheading("Estado de las políticas"));
        PdfPTable statuses = new PdfPTable(3);
        statuses.setWidthPercentage(100);
        statuses.setSpacingAfter(22);
        for (String status : STATUS_ORDER) {
            PdfPCell header = headerCell(statusLabel(status));
            header.setHorizontalAlignment(Element.ALIGN_CENTER);
            statuses.addCell(header);
        }
        int[] statusCounts = {summary.nonCompliantPolicies(), summary.requiresReviewPolicies(), summary.compliantPolicies()};
        for (int i = 0; i < STATUS_ORDER.size(); i++) {
            PdfPCell value = cell(new Phrase(String.valueOf(statusCounts[i]),
                    withColor(H2, statusColor(STATUS_ORDER.get(i)))), WHITE);
            value.setHorizontalAlignment(Element.ALIGN_CENTER);
            value.setPadding(7);
            statuses.addCell(value);
        }
        document.add(statuses);
    }

    private PdfPCell kpiCell(String value, String label, Color valueColor) {
        PdfPCell cell = new PdfPCell();
        cell.setBorderColor(BORDER);
        cell.setBorderWidth(0.6f);
        cell.setPadding(9);
        Paragraph number = new Paragraph(value, withColor(KPI_VALUE, valueColor));
        number.setAlignment(Element.ALIGN_CENTER);
        cell.addElement(number);
        Paragraph caption = new Paragraph(label, KPI_LABEL);
        caption.setAlignment(Element.ALIGN_CENTER);
        cell.addElement(caption);
        return cell;
    }

    // ---- 2. Category coverage ------------------------------------------------------

    private void addCategoryCoverage(Document document, List<CategoryCoverage> coverage) throws DocumentException {
        addSectionHeading(document, CATEGORY_COVERAGE);
        Paragraph intro = new Paragraph("Distribución de las políticas evaluadas y de los hallazgos en las cinco "
                + "categorías del catálogo de SegSoft. Una categoría sin políticas evaluadas no tiene cobertura "
                + "en este análisis.", BODY);
        intro.setSpacingAfter(10);
        document.add(intro);

        PdfPTable table = new PdfPTable(new float[]{2.6f, 1f, 1f, 1f, 1f, 1f, 1.1f, 1.3f});
        table.setWidthPercentage(100);
        table.setHeaderRows(1);
        for (String header : List.of("Categoría", "Políticas", "Cumplen", "No cumplen", "Revisión",
                "Hallazgos", "Altos / críticos", "Cumplimiento")) {
            table.addCell(headerCell(header));
        }

        Map<String, CategoryCoverage> byCategory = coverage.stream()
                .collect(Collectors.toMap(CategoryCoverage::category, c -> c, (a, b) -> a));
        int row = 0;
        for (String category : CATALOG_CATEGORIES) {
            CategoryCoverage item = byCategory.getOrDefault(category,
                    new CategoryCoverage(category, 0, 0, 0, 0, 0, 0));
            Color background = row++ % 2 == 0 ? WHITE : ZEBRA;
            table.addCell(cell(new Phrase(categoryLabel(category), TABLE_CELL_BOLD), background));
            table.addCell(numberCell(item.policiesEvaluated(), background));
            table.addCell(numberCell(item.compliantPolicies(), background));
            table.addCell(numberCell(item.nonCompliantPolicies(), background));
            table.addCell(numberCell(item.requiresReviewPolicies(), background));
            table.addCell(numberCell(item.findings(), background));
            table.addCell(numberCell(item.highOrCriticalFindings(), background));
            PdfPCell compliance;
            if (item.policiesEvaluated() == 0) {
                compliance = cell(new Phrase("Sin cobertura", withColor(TABLE_CELL, MUTED)), background);
            } else {
                double pct = item.compliantPolicies() * 100.0 / item.policiesEvaluated();
                compliance = cell(new Phrase(percent(pct), withColor(TABLE_CELL_BOLD, complianceColor(pct))), background);
            }
            compliance.setHorizontalAlignment(Element.ALIGN_RIGHT);
            table.addCell(compliance);
        }
        document.add(table);
    }

    // ---- 3. Policy results ---------------------------------------------------------

    private void addPolicyResults(Document document, List<PolicyEntry> policies) throws DocumentException {
        addSectionHeading(document, POLICY_RESULTS);
        if (policies.isEmpty()) {
            document.add(new Paragraph("El análisis no produjo resultados por política.", BODY));
            return;
        }
        Paragraph intro = new Paragraph("Resultado de cada política seleccionada, primero las que no cumplen. "
                + "El peso indica la criticidad de la política en el cumplimiento ponderado.", BODY);
        intro.setSpacingAfter(10);
        document.add(intro);

        PdfPTable table = new PdfPTable(new float[]{2.9f, 1.7f, 1.75f, 0.7f, 1.3f, 1.1f, 1.1f});
        table.setWidthPercentage(100);
        table.setHeaderRows(1);
        for (String header : List.of("Política", "Categoría", "Marco / control", "Peso", "Estado",
                "Hallazgos", "Altos / críticos")) {
            table.addCell(headerCell(header));
        }

        List<PolicyEntry> sorted = policies.stream()
                .sorted(Comparator.comparingInt((PolicyEntry p) -> rank(STATUS_ORDER, p.status()))
                        .thenComparing(p -> orDash(p.name()), String.CASE_INSENSITIVE_ORDER))
                .toList();
        int row = 0;
        for (PolicyEntry policy : sorted) {
            Color background = row++ % 2 == 0 ? WHITE : ZEBRA;
            table.addCell(cell(new Phrase(pdfText(orDash(sanitizer.field(policy.name()))), TABLE_CELL_BOLD), background));
            table.addCell(cell(new Phrase(categoryLabel(policy.category()), TABLE_CELL), background));
            String control = sanitizer.field(policy.controlId());
            String framework = frameworkLabel(policy.framework()) + (control.isEmpty() ? "" : " · " + control);
            table.addCell(cell(new Phrase(pdfText(framework), TABLE_CELL), background));
            table.addCell(numberCell(policy.weight() != null ? policy.weight() : 0, background));
            table.addCell(cell(new Phrase(statusLabel(policy.status()),
                    withColor(TABLE_CELL_BOLD, statusColor(policy.status()))), background));
            table.addCell(numberCell(policy.findingsCount(), background));
            table.addCell(numberCell(policy.highOrCriticalCount(), background));
        }
        document.add(table);
    }

    // ---- 4. Findings ---------------------------------------------------------------

    /** Minimum room (pt) left on the page to start a severity group there. */
    private static final float MIN_SPACE_FOR_GROUP = 150;

    private void addFindings(Document document, PdfWriter writer, List<FindingEntry> findings)
            throws DocumentException {
        addSectionHeading(document, FINDINGS);
        if (findings.isEmpty()) {
            document.add(new Paragraph("No se identificaron hallazgos en este análisis.", BODY));
            return;
        }
        Paragraph intro = new Paragraph(plural(findings.size(), "hallazgo", "hallazgos") + " ordenados por severidad, de crítica a baja. "
                + "Los fragmentos de evidencia se muestran con los secretos enmascarados.", BODY);
        intro.setSpacingAfter(6);
        document.add(intro);

        List<String> severityOrder = Arrays.asList(SEVERITY_ORDER);
        List<FindingEntry> sorted = findings.stream()
                .sorted(Comparator.comparingInt((FindingEntry f) -> rank(severityOrder, f.severity()))
                        .thenComparing(f -> orDash(f.policyName()), String.CASE_INSENSITIVE_ORDER)
                        .thenComparing(f -> orDash(f.filePath()))
                        .thenComparing(f -> f.lineNumber() != null ? f.lineNumber() : 0))
                .toList();

        String currentSeverity = null;
        int number = 0;
        for (FindingEntry finding : sorted) {
            if (!finding.severity().equals(currentSeverity)) {
                currentSeverity = finding.severity();
                // Never leave a group heading orphaned at the bottom of a page.
                if (writer.getVerticalPosition(true) - document.bottom() < MIN_SPACE_FOR_GROUP) {
                    document.newPage();
                }
                String severity = currentSeverity;
                long count = sorted.stream().filter(f -> severity.equals(f.severity())).count();
                Paragraph group = subheading("Severidad " + severityLabel(severity).toLowerCase(ES_CO)
                        + " (" + count + ")");
                group.setSpacingBefore(10);
                document.add(group);
            }
            document.add(findingBlock(++number, finding));
        }
    }

    private PdfPTable findingBlock(int number, FindingEntry finding) {
        PdfPTable block = new PdfPTable(new float[]{0.06f, 3.94f});
        block.setWidthPercentage(100);
        block.setSpacingAfter(8);
        block.setKeepTogether(true);

        PdfPCell strip = new PdfPCell();
        strip.setBackgroundColor(severityFill(finding.severity()));
        strip.setBorder(Rectangle.NO_BORDER);
        block.addCell(strip);

        PdfPCell body = new PdfPCell();
        body.setBorderColor(BORDER);
        body.setBorderWidth(0.6f);
        body.setPadding(7);

        Paragraph title = new Paragraph();
        title.add(new Chunk("#" + number + "  ", SMALL_BOLD));
        Chunk badge = new Chunk(" " + severityLabel(finding.severity()).toUpperCase(ES_CO) + " ",
                withColor(SMALL_BOLD, severityTextOnFill(finding.severity())));
        badge.setBackground(severityFill(finding.severity()), 1, 2, 1, 1);
        title.add(badge);
        title.add(new Chunk("   " + pdfText(orDash(sanitizer.field(finding.policyName()))), BODY_BOLD));
        body.addElement(title);

        StringBuilder classification = new StringBuilder("Categoría: ").append(categoryLabel(finding.category()));
        String cwe = sanitizer.field(finding.cweId());
        if (!cwe.isEmpty()) {
            classification.append("   ·   ").append(cwe);
        }
        Paragraph details = new Paragraph(pdfText(classification.toString()), SMALL);
        details.setSpacingBefore(3);
        body.addElement(details);

        Paragraph location = new Paragraph();
        location.setSpacingBefore(3);
        location.add(new Chunk("Ubicación: ", SMALL_BOLD));
        String line = finding.lineNumber() != null ? ":" + finding.lineNumber() : "";
        location.add(new Chunk(pdfText(orDash(sanitizer.field(finding.filePath())) + line), MONO));
        body.addElement(location);

        String snippet = sanitizer.snippet(finding.evidenceSnippet());
        if (!snippet.isEmpty()) {
            PdfPTable evidence = new PdfPTable(1);
            evidence.setWidthPercentage(100);
            evidence.setSpacingBefore(5);
            PdfPCell evidenceCell = cell(monospaceBlock(snippet), SNIPPET_BG);
            evidenceCell.setPadding(6);
            evidenceCell.setPaddingTop(4);
            evidence.addCell(evidenceCell);
            body.addElement(evidence);
        }

        String action = sanitizer.text(finding.suggestedAction());
        if (!action.isEmpty()) {
            Paragraph suggested = new Paragraph();
            suggested.setSpacingBefore(5);
            suggested.add(new Chunk("Acción sugerida: ", SMALL_BOLD));
            suggested.add(new Chunk(pdfText(action), withColor(SMALL, TEXT)));
            body.addElement(suggested);
        }
        block.addCell(body);
        return block;
    }

    // ---- Building blocks -------------------------------------------------------------

    private static Paragraph subheading(String text) {
        Paragraph paragraph = new Paragraph(text, H2);
        paragraph.setSpacingAfter(6);
        return paragraph;
    }

    /**
     * Multi-line code: one chunk per line, each carrying the monospace font.
     * A single chunk with embedded newlines loses its font after the first
     * line break when laid out in a table cell.
     */
    private static Phrase monospaceBlock(String text) {
        Phrase phrase = new Phrase(MONO.getSize() * 1.45f);
        String[] lines = text.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                phrase.add(new Chunk("\n", MONO));
            }
            phrase.add(new Chunk(pdfText(lines[i]), MONO));
        }
        return phrase;
    }

    private static PdfPCell headerCell(String text) {
        PdfPCell cell = cell(new Phrase(text, TABLE_HEADER), PRIMARY);
        cell.setBorderColor(PRIMARY);
        return cell;
    }

    private static PdfPCell numberCell(int value, Color background) {
        PdfPCell cell = cell(new Phrase(String.valueOf(value), TABLE_CELL), background);
        cell.setHorizontalAlignment(Element.ALIGN_RIGHT);
        return cell;
    }

    private static PdfPCell cell(Phrase phrase, Color background) {
        PdfPCell cell = new PdfPCell(phrase);
        cell.setBackgroundColor(background);
        cell.setBorderColor(BORDER);
        cell.setBorderWidth(0.5f);
        cell.setPadding(CELL_PADDING);
        cell.setVerticalAlignment(Element.ALIGN_MIDDLE);
        return cell;
    }

    // ---- Formatting helpers -------------------------------------------------------------

    private String date(OffsetDateTime value) {
        return value == null ? "—" : dateFormat.format(value);
    }

    private static int severityCount(Summary summary, String severity) {
        Map<String, Integer> counts = summary.findingsBySeverity();
        return counts == null ? 0 : counts.getOrDefault(severity, 0);
    }

    private static String percent(BigDecimal value) {
        return percent(toDouble(value));
    }

    private static String percent(double value) {
        DecimalFormat format = new DecimalFormat("0.#", DecimalFormatSymbols.getInstance(ES_CO));
        return format.format(value) + " %";
    }

    private static double toDouble(BigDecimal value) {
        return value == null ? 0 : value.doubleValue();
    }

    private static String plural(int count, String singular, String pluralForm) {
        return count + " " + (count == 1 ? singular : pluralForm);
    }

    private static int rank(List<String> order, String value) {
        int index = order.indexOf(value);
        return index < 0 ? order.size() : index;
    }

    private static String orDash(String value) {
        return value == null || value.isBlank() ? "—" : value;
    }

    /**
     * The base-14 fonts only cover WinAnsi (Windows-1252); characters outside
     * it would silently disappear, so they are replaced by '?' instead.
     */
    static String pdfText(String value) {
        if (value == null) {
            return "";
        }
        CharsetEncoder encoder = WIN_ANSI.newEncoder();
        StringBuilder result = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            String character = new String(Character.toChars(codePoint));
            result.append(codePoint == '\n' || encoder.canEncode(character) ? character : "?");
        });
        return result.toString();
    }
}
