package co.icesi.pdgseg.exception;

import java.util.List;

public class UnsupportedExportFormatException extends RuntimeException {

    private final List<String> supportedFormats;

    public UnsupportedExportFormatException(String requestedFormat, List<String> supportedFormats) {
        super("Formato de exportación no soportado: '" + requestedFormat + "'. Formatos soportados: "
                + String.join(", ", supportedFormats));
        this.supportedFormats = List.copyOf(supportedFormats);
    }

    public List<String> getSupportedFormats() {
        return supportedFormats;
    }
}
