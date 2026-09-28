package co.icesi.pdgseg.export;

import co.icesi.pdgseg.exception.UnsupportedExportFormatException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class ReportExporterRegistry {

    private final Map<String, ReportExporter> exportersByFormat;

    public ReportExporterRegistry(List<ReportExporter> exporters) {
        this.exportersByFormat = exporters.stream()
                .collect(Collectors.toMap(
                        exporter -> normalize(exporter.format()),
                        Function.identity(),
                        (a, b) -> {
                            throw new IllegalStateException("Dos exportadores registran el formato '" + a.format() + "'");
                        },
                        TreeMap::new));
    }

    public ReportExporter resolve(String format) {
        ReportExporter exporter = format == null ? null : exportersByFormat.get(normalize(format));
        if (exporter == null) {
            throw new UnsupportedExportFormatException(format, supportedFormats());
        }
        return exporter;
    }

    public List<String> supportedFormats() {
        return List.copyOf(exportersByFormat.keySet());
    }

    private static String normalize(String format) {
        return format.trim().toLowerCase(Locale.ROOT);
    }
}
