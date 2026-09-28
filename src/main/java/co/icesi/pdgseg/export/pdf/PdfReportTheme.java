package co.icesi.pdgseg.export.pdf;

import com.lowagie.text.Font;

import java.awt.Color;
import java.util.Map;

/**
 * Visual template of the exported PDF: typography, palette and the Spanish
 * labels shown for domain enums. Severity colors mirror the frontend's
 * SEVERITY_HEX (src/utils/severityColors.ts) so a finding reads the same in
 * the app and on paper. See segsoft-docs/reporte-pdf-plantilla.md.
 */
final class PdfReportTheme {

    private PdfReportTheme() {
    }

    // ---- Palette ----------------------------------------------------------
    static final Color PRIMARY = new Color(0x1F, 0x2A, 0x44);
    static final Color ACCENT = new Color(0x25, 0x63, 0xEB);
    static final Color TEXT = new Color(0x11, 0x18, 0x27);
    static final Color MUTED = new Color(0x6B, 0x72, 0x80);
    static final Color BORDER = new Color(0xD1, 0xD5, 0xDB);
    static final Color ZEBRA = new Color(0xF3, 0xF4, 0xF6);
    static final Color SNIPPET_BG = new Color(0xF8, 0xFA, 0xFC);
    static final Color WHITE = Color.WHITE;

    static final Color COMPLIANT = new Color(0x15, 0x80, 0x3D);
    static final Color NON_COMPLIANT = new Color(0xB9, 0x1C, 0x1C);
    static final Color REQUIRES_REVIEW = new Color(0xB4, 0x53, 0x09);

    private static final Map<String, Color> SEVERITY_FILL = Map.of(
            "CRITICAL", new Color(0xD0, 0x3B, 0x3B),
            "HIGH", new Color(0xEC, 0x83, 0x5A),
            "MEDIUM", new Color(0xFA, 0xB2, 0x19),
            "LOW", new Color(0x0C, 0xA3, 0x0C)
    );
    private static final Color DARK_ON_FILL = new Color(0x0B, 0x0B, 0x0B);

    // ---- Typography: base-14 fonts (no embedding, WinAnsi covers Spanish) --
    static final Font COVER_KICKER = font(Font.HELVETICA, 10, Font.BOLD, ACCENT);
    static final Font COVER_TITLE = font(Font.HELVETICA, 26, Font.BOLD, PRIMARY);
    static final Font COVER_SUBTITLE = font(Font.HELVETICA, 14, Font.NORMAL, MUTED);
    static final Font H1 = font(Font.HELVETICA, 16, Font.BOLD, PRIMARY);
    static final Font H2 = font(Font.HELVETICA, 11.5f, Font.BOLD, PRIMARY);
    static final Font BODY = font(Font.HELVETICA, 9.5f, Font.NORMAL, TEXT);
    static final Font BODY_BOLD = font(Font.HELVETICA, 9.5f, Font.BOLD, TEXT);
    static final Font SMALL = font(Font.HELVETICA, 8, Font.NORMAL, MUTED);
    static final Font SMALL_BOLD = font(Font.HELVETICA, 8, Font.BOLD, TEXT);
    static final Font TABLE_HEADER = font(Font.HELVETICA, 8, Font.BOLD, WHITE);
    static final Font TABLE_CELL = font(Font.HELVETICA, 8.5f, Font.NORMAL, TEXT);
    static final Font TABLE_CELL_BOLD = font(Font.HELVETICA, 8.5f, Font.BOLD, TEXT);
    static final Font KPI_VALUE = font(Font.HELVETICA, 20, Font.BOLD, PRIMARY);
    static final Font KPI_LABEL = font(Font.HELVETICA, 7.5f, Font.NORMAL, MUTED);
    static final Font MONO = font(Font.COURIER, 7.5f, Font.NORMAL, TEXT);
    static final Font MONO_SMALL = font(Font.COURIER, 6.5f, Font.NORMAL, MUTED);
    static final Font TOC_ENTRY = font(Font.HELVETICA, 11, Font.NORMAL, TEXT);
    static final Font HEADER_FOOTER = font(Font.HELVETICA, 7.5f, Font.NORMAL, MUTED);

    // ---- Page geometry (points) -------------------------------------------
    static final float MARGIN_SIDE = 50;
    static final float MARGIN_TOP = 62;
    static final float MARGIN_BOTTOM = 64;
    static final float CELL_PADDING = 4.5f;

    // ---- Labels -------------------------------------------------------------
    static final String[] SEVERITY_ORDER = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};

    private static final Map<String, String> SEVERITY_LABELS = Map.of(
            "CRITICAL", "Crítica", "HIGH", "Alta", "MEDIUM", "Media", "LOW", "Baja");

    private static final Map<String, String> STATUS_LABELS = Map.of(
            "COMPLIANT", "Cumple", "NON_COMPLIANT", "No cumple", "REQUIRES_REVIEW", "Requiere revisión");

    private static final Map<String, String> CATEGORY_LABELS = Map.of(
            "SQL_INJECTION", "Inyección SQL",
            "XSS", "Cross-Site Scripting (XSS)",
            "AUTHENTICATION_FAILURE", "Fallas de autenticación",
            "INSECURE_DATA_HANDLING", "Manejo inseguro de datos",
            "DEPENDENCY_VULNERABILITY", "Dependencias vulnerables");

    private static final Map<String, String> FRAMEWORK_LABELS = Map.of(
            "ISO_27001", "ISO/IEC 27001",
            "OWASP_TOP_10_2021", "OWASP Top 10 2021",
            "OWASP_ASVS", "OWASP ASVS",
            "NIST_SP_800_53", "NIST SP 800-53",
            "CUSTOM", "Personalizado",
            "DEVSECOPS", "DevSecOps");

    static String severityLabel(String severity) {
        return label(SEVERITY_LABELS, severity);
    }

    static String statusLabel(String status) {
        return label(STATUS_LABELS, status);
    }

    static String categoryLabel(String category) {
        return label(CATEGORY_LABELS, category);
    }

    static String frameworkLabel(String framework) {
        return label(FRAMEWORK_LABELS, framework);
    }

    static Color severityFill(String severity) {
        return SEVERITY_FILL.getOrDefault(severity, MUTED);
    }

    static Color severityTextOnFill(String severity) {
        return "CRITICAL".equals(severity) ? WHITE : DARK_ON_FILL;
    }

    static Color statusColor(String status) {
        if ("COMPLIANT".equals(status)) {
            return COMPLIANT;
        }
        if ("NON_COMPLIANT".equals(status)) {
            return NON_COMPLIANT;
        }
        return REQUIRES_REVIEW;
    }

    /** Traffic-light color for a compliance percentage. */
    static Color complianceColor(double percentage) {
        if (percentage >= 80) {
            return COMPLIANT;
        }
        return percentage >= 50 ? REQUIRES_REVIEW : NON_COMPLIANT;
    }

    static Font withColor(Font base, Color color) {
        return font(base.getFamily(), base.getSize(), base.getStyle(), color);
    }

    private static String label(Map<String, String> labels, String key) {
        if (key == null || key.isBlank()) {
            return "—";
        }
        return labels.getOrDefault(key, key);
    }

    private static Font font(int family, float size, int style, Color color) {
        return new Font(family, size, style, color);
    }
}
