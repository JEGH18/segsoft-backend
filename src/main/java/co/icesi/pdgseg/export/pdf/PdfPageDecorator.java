package co.icesi.pdgseg.export.pdf;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfPageEventHelper;
import com.lowagie.text.pdf.PdfWriter;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Draws the running header (from page 2 on) and the footer present on every
 * page: report id, "Página X de Y" and the report checksum. It also records
 * the page each section heading landed on (via Chunk generic tags), which the
 * exporter's second pass uses to fill in the table of contents.
 */
class PdfPageDecorator extends PdfPageEventHelper {

    private final String headerText;
    private final String footerLeft;
    private final String checksumLine;
    private final int totalPages;
    private final Map<String, Integer> sectionPages = new LinkedHashMap<>();

    /**
     * @param totalPages total page count from a previous pass, or 0 when
     *                   still unknown (first pass), in which case the footer
     *                   omits the "de Y" part.
     */
    PdfPageDecorator(String headerText, String footerLeft, String checksum, int totalPages) {
        this.headerText = headerText;
        this.footerLeft = footerLeft;
        this.checksumLine = "Checksum SHA-256 del reporte: " + checksum;
        this.totalPages = totalPages;
    }

    Map<String, Integer> sectionPages() {
        return sectionPages;
    }

    @Override
    public void onGenericTag(PdfWriter writer, Document document, Rectangle rect, String text) {
        sectionPages.putIfAbsent(text, writer.getPageNumber());
    }

    @Override
    public void onEndPage(PdfWriter writer, Document document) {
        PdfContentByte canvas = writer.getDirectContent();
        int page = writer.getPageNumber();
        float left = document.left();
        float right = document.right();

        if (page > 1) {
            float headerY = document.top() + 22;
            ColumnText.showTextAligned(canvas, Element.ALIGN_LEFT,
                    new Phrase("SegSoft · Reporte de cumplimiento", PdfReportTheme.HEADER_FOOTER), left, headerY, 0);
            ColumnText.showTextAligned(canvas, Element.ALIGN_RIGHT,
                    new Phrase(headerText, PdfReportTheme.HEADER_FOOTER), right, headerY, 0);
            drawRule(canvas, left, right, headerY - 6);
        }

        float footerY = document.bottom() - 26;
        drawRule(canvas, left, right, footerY + 12);
        ColumnText.showTextAligned(canvas, Element.ALIGN_LEFT,
                new Phrase(footerLeft, PdfReportTheme.HEADER_FOOTER), left, footerY, 0);
        String pageLabel = totalPages > 0 ? "Página " + page + " de " + totalPages : "Página " + page;
        ColumnText.showTextAligned(canvas, Element.ALIGN_RIGHT,
                new Phrase(pageLabel, PdfReportTheme.HEADER_FOOTER), right, footerY, 0);
        ColumnText.showTextAligned(canvas, Element.ALIGN_LEFT,
                new Phrase(checksumLine, PdfReportTheme.MONO_SMALL), left, footerY - 11, 0);
    }

    private static void drawRule(PdfContentByte canvas, float left, float right, float y) {
        canvas.saveState();
        canvas.setColorStroke(PdfReportTheme.BORDER);
        canvas.setLineWidth(0.6f);
        canvas.moveTo(left, y);
        canvas.lineTo(right, y);
        canvas.stroke();
        canvas.restoreState();
    }
}
