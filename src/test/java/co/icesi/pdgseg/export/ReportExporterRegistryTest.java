package co.icesi.pdgseg.export;

import co.icesi.pdgseg.dto.report.ReportDocument;
import co.icesi.pdgseg.exception.UnsupportedExportFormatException;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReportExporterRegistryTest {

    private static ReportExporter exporter(String format) {
        return new ReportExporter() {
            @Override
            public String format() {
                return format;
            }

            @Override
            public MediaType mediaType() {
                return MediaType.APPLICATION_OCTET_STREAM;
            }

            @Override
            public String fileExtension() {
                return format;
            }

            @Override
            public byte[] export(ReportDocument report) {
                return new byte[0];
            }
        };
    }

    private final ReportExporter pdf = exporter("pdf");
    private final ReportExporter sarif = exporter("sarif");
    private final ReportExporterRegistry registry = new ReportExporterRegistry(List.of(pdf, sarif));

    @Test
    void resolvesExporterByFormatIgnoringCaseAndSurroundingSpaces() {
        assertThat(registry.resolve("pdf")).isSameAs(pdf);
        assertThat(registry.resolve("PDF")).isSameAs(pdf);
        assertThat(registry.resolve(" pdf ")).isSameAs(pdf);
        assertThat(registry.resolve("sarif")).isSameAs(sarif);
    }

    @Test
    void newExporterBecomesAvailableWithoutChangingTheRegistry() {
        assertThat(registry.supportedFormats()).containsExactly("pdf", "sarif");
    }

    @Test
    void unsupportedFormatReportsTheSupportedOnes() {
        assertThatThrownBy(() -> registry.resolve("docx"))
                .isInstanceOf(UnsupportedExportFormatException.class)
                .hasMessageContaining("docx")
                .hasMessageContaining("pdf, sarif")
                .satisfies(ex -> assertThat(((UnsupportedExportFormatException) ex).getSupportedFormats())
                        .containsExactly("pdf", "sarif"));
    }

    @Test
    void missingFormatIsUnsupported() {
        assertThatThrownBy(() -> registry.resolve(null)).isInstanceOf(UnsupportedExportFormatException.class);
    }

    @Test
    void twoExportersForTheSameFormatAreRejectedAtStartup() {
        assertThatThrownBy(() -> new ReportExporterRegistry(List.of(exporter("pdf"), exporter("PDF"))))
                .isInstanceOf(IllegalStateException.class);
    }
}
