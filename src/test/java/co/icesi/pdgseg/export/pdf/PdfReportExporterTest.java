package co.icesi.pdgseg.export.pdf;

import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.export.ReportFixtures;
import co.icesi.pdgseg.export.ReportTextSanitizer;
import co.icesi.pdgseg.service.SecretMaskingService;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validity and confidentiality of the exported PDF. The file is parsed back
 * with PDFBox -- an independent implementation, not the library that wrote
 * it -- so these assertions hold for what a PDF reader actually sees.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PdfReportExporterTest {

    private PdfReportExporter exporter;
    private ReportDocument report;
    private byte[] pdf;
    private List<String> pages;
    private String fullText;
    /** fullText without any whitespace: immune to line wrapping inside table cells. */
    private String compactText;

    @BeforeAll
    void exportFixture() throws IOException {
        exporter = new PdfReportExporter(new ReportTextSanitizer(new SecretMaskingService()), "America/Bogota");
        report = ReportFixtures.documentWithSecrets();
        pdf = exporter.export(report);
        pages = extractPages(pdf);
        fullText = String.join("\n", pages);
        compactText = compact(fullText);
    }

    // ---- Validity -------------------------------------------------------------------

    @Test
    void exportsAParseablePdfDocument() throws IOException {
        assertThat(new String(pdf, 0, 5, StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
        assertThat(new String(pdf, StandardCharsets.ISO_8859_1).stripTrailing()).endsWith("%%EOF");
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.isEncrypted()).isFalse();
            assertThat(document.getNumberOfPages()).isGreaterThanOrEqualTo(5);
            PDDocumentInformation info = document.getDocumentInformation();
            assertThat(info.getTitle()).isEqualTo("Reporte de cumplimiento - " + ReportFixtures.REPOSITORY_NAME);
            assertThat(info.getAuthor()).isEqualTo("SegSoft");
        }
    }

    @Test
    void exporterAdvertisesPdfFormat() {
        assertThat(exporter.format()).isEqualTo("pdf");
        assertThat(exporter.mediaType().toString()).isEqualTo("application/pdf");
        assertThat(exporter.fileExtension()).isEqualTo("pdf");
    }

    // ---- Mandatory sections --------------------------------------------------------------

    @Test
    void coverPageContainsTheReportMetadata() {
        String cover = normalize(pages.get(0));
        assertThat(cover)
                .contains("Reporte de cumplimiento de políticas de seguridad")
                .contains(ReportFixtures.REPOSITORY_NAME)
                .contains("Identificador del reporte")
                .contains(report.reportId().toString())
                .contains("Generado")
                .contains("Generado por")
                .contains("auditor")
                .contains("Reglas ejecutadas")
                .contains("24 de 24")
                .contains("rama main")
                .contains(ReportFixtures.CHECKSUM);
    }

    @Test
    void containsEveryMandatorySection() {
        assertThat(compactText)
                .contains("Índice")
                .contains("1.Resumenejecutivo")
                .contains("2.Coberturaporcategoría")
                .contains("3.Resultadosporpolítica")
                .contains("4.Hallazgosdetallados");
    }

    @Test
    void executiveSummaryStatesComplianceAndFindingTotals() {
        String summary = normalize(sectionText("1. Resumen ejecutivo", "2. Cobertura por categoría"));
        assertThat(summary)
                .contains("60 %")
                .contains("55,5 %")
                .contains("Crítica").contains("Alta").contains("Media").contains("Baja")
                .contains("se registró 1 error de regla")
                .contains("1 no cumple y 1 requiere revisión");
        assertThat(compact(summary)).contains("Hallazgosporseveridad").contains("Estadodelaspolíticas");
    }

    @Test
    void coverageListsAllFiveCatalogCategoriesEvenWithoutPolicies() {
        String coverage = sectionText("2. Cobertura por categoría", "3. Resultados por política");
        assertThat(coverage)
                .contains("Inyección SQL")
                .contains("Cross-Site Scripting (XSS)")
                .contains("Fallas de autenticación")
                .contains("Manejo inseguro de datos")
                .contains("Dependencias vulnerables")
                .contains("Sin cobertura");
    }

    @Test
    void policyResultsListEveryPolicyWithNonCompliantFirst() {
        String results = sectionText("3. Resultados por política", "4. Hallazgos detallados");
        // Long names wrap inside their cell and interleave with the neighbouring
        // columns in the extracted text, so only the order of their words is checked.
        report.content().policyResults().forEach(policy -> assertThat(results)
                .containsPattern(Pattern.compile(String.join(".*?", policy.name().split(" ")), Pattern.DOTALL)));
        String rows = compact(results);
        assertThat(rows.indexOf("Nocumple")).isNotNegative();
        assertThat(rows.indexOf("Nocumple")).isLessThan(rows.indexOf("Requiererevisión"));
        assertThat(rows.indexOf("Requiererevisión")).isLessThan(rows.lastIndexOf("Cumple"));
    }

    @Test
    void findingsAreOrderedFromCriticalToLow() {
        String findings = compactText.substring(compactText.lastIndexOf("4.Hallazgosdetallados"));
        int critical = findings.indexOf("Severidadcrítica(1)");
        int high = findings.indexOf("Severidadalta(1)");
        int medium = findings.indexOf("Severidadmedia(2)");
        int low = findings.indexOf("Severidadbaja(1)");
        assertThat(critical).isNotNegative();
        assertThat(critical).isLessThan(high);
        assertThat(high).isLessThan(medium);
        assertThat(medium).isLessThan(low);
        assertThat(findings.indexOf("src/db/UserDao.java:42")).isBetween(critical, high);
        assertThat(findings.indexOf("src/db/OrderDao.java:88")).isBetween(high, medium);
        assertThat(findings.indexOf("src/web/banner.js:3")).isGreaterThan(low);
    }

    @Test
    void everyPageIsNumberedAndCarriesTheChecksumInItsFooter() {
        int total = pages.size();
        for (int i = 0; i < total; i++) {
            assertThat(pages.get(i))
                    .as("página %d", i + 1)
                    .contains("Página " + (i + 1) + " de " + total)
                    .contains(ReportFixtures.CHECKSUM);
        }
    }

    @Test
    void tableOfContentsPointsToThePageWhereEachSectionStarts() {
        String toc = pages.get(1);
        for (PdfReportExporter.Section section : PdfReportExporter.SECTIONS) {
            int page = firstPageContaining(section.title(), 2) + 1;
            assertThat(toc).containsPattern(Pattern.quote(section.title()) + "\\s*\\.*\\s*" + page + "\\b");
        }
    }

    @Test
    void reportWithoutResultsStillRendersEverySection() throws IOException {
        String text = String.join("\n", extractPages(exporter.export(ReportFixtures.emptyDocument())));
        assertThat(text)
                .contains("1. Resumen ejecutivo")
                .contains("Dependencias vulnerables")
                .contains("El análisis no produjo resultados por política.")
                .contains("No se identificaron hallazgos en este análisis.");
    }

    // ---- Confidentiality ----------------------------------------------------------------

    @Test
    void noPlantedSecretAppearsInClearText() {
        // Whitespace is removed so a secret wrapped across two lines is still caught.
        for (String secret : ReportFixtures.PLANTED_SECRETS) {
            assertThat(compactText).as("secreto en claro: %s", secret).doesNotContain(secret);
        }
    }

    @Test
    void snippetsShowOnlyMaskedValues() {
        assertThat(compactText)
                .contains("api_key=*****")
                .contains("apiKey=\"*****\"")
                .contains("password:\"*****\"")
                .contains("Bearer*****")
                .contains("-----BEGINRSAPRIVATEKEY-----*****-----ENDRSAPRIVATEKEY-----")
                .contains("db_password=*****");
    }

    @Test
    void documentMetadataDoesNotLeakSecrets() throws IOException {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            PDDocumentInformation info = document.getDocumentInformation();
            String metadata = String.join("|", info.getTitle(), info.getSubject(), info.getKeywords(),
                    info.getAuthor(), info.getCreator());
            ReportFixtures.PLANTED_SECRETS.forEach(secret -> assertThat(metadata).doesNotContain(secret));
        }
    }

    @Test
    void controlAndBidiCharactersAreStripped() {
        assertThat(fullText).doesNotContain("‮").doesNotContain("​").doesNotContain("\u0000");
        assertThat(compactText).contains("keys/deploy.pem:1");
    }

    // ---- Helpers ------------------------------------------------------------------------

    private static List<String> extractPages(byte[] bytes) throws IOException {
        try (PDDocument document = Loader.loadPDF(bytes)) {
            PDFTextStripper stripper = new PDFTextStripper();
            // OpenPDF writes table text after the page's paragraphs in the content
            // stream; sorting by position yields the order a reader sees.
            stripper.setSortByPosition(true);
            List<String> result = new ArrayList<>();
            for (int page = 1; page <= document.getNumberOfPages(); page++) {
                stripper.setStartPage(page);
                stripper.setEndPage(page);
                result.add(stripper.getText(document));
            }
            return result;
        }
    }

    /** Index (0-based) of the first page from {@code fromIndex} whose text contains {@code text}. */
    private int firstPageContaining(String text, int fromIndex) {
        for (int i = fromIndex; i < pages.size(); i++) {
            if (pages.get(i).contains(text)) {
                return i;
            }
        }
        throw new AssertionError("Ninguna página contiene: " + text);
    }

    private String sectionText(String start, String end) {
        int from = fullText.lastIndexOf(start);
        int to = fullText.lastIndexOf(end);
        return fullText.substring(from, to);
    }

    private static String compact(String text) {
        return text.replaceAll("\\s+", "");
    }

    private static String normalize(String text) {
        return text.replaceAll("\\s+", " ");
    }
}
