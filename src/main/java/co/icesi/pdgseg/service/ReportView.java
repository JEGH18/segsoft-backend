package co.icesi.pdgseg.service;

import co.icesi.pdgseg.exception.BusinessValidationException;

import java.util.Locale;

/** GET /api/v1/reports/{id}?view=technical|executive */
public enum ReportView {
    TECHNICAL,
    EXECUTIVE;

    public static ReportView parse(String value) {
        if (value == null || value.isBlank()) {
            return TECHNICAL;
        }
        try {
            return valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new BusinessValidationException(
                    "Vista no soportada: '" + value + "'. Vistas disponibles: technical, executive");
        }
    }

    public String key() {
        return name().toLowerCase(Locale.ROOT);
    }
}
