package co.icesi.pdgseg.export.cache;

import co.icesi.pdgseg.exception.ExportTooLargeException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExportSizeLimitTest {

    private static final long MB = 1024L * 1024L;

    @Test
    void acceptsFilesUpToTheLimit() {
        ExportSizeLimit limit = new ExportSizeLimit(1);
        assertThatCode(() -> limit.check(MB)).doesNotThrowAnyException();
    }

    @Test
    void rejectsFilesAboveAReducedLimitWithAMessageThatStatesIt() {
        ExportSizeLimit limit = new ExportSizeLimit(1);

        assertThatThrownBy(() -> limit.check(MB + 1))
                .isInstanceOf(ExportTooLargeException.class)
                .hasMessageContaining("1 MB")
                .hasMessageContaining("MAX_EXPORT_SIZE_MB")
                .satisfies(ex -> {
                    assertThat(((ExportTooLargeException) ex).getMaxSizeMb()).isEqualTo(1);
                    assertThat(((ExportTooLargeException) ex).getSizeBytes()).isEqualTo(MB + 1);
                });
    }

    @Test
    void defaultOfFiftyMegabytes() {
        ExportSizeLimit limit = new ExportSizeLimit(50);
        assertThatCode(() -> limit.check(50 * MB)).doesNotThrowAnyException();
        assertThatThrownBy(() -> limit.check(50 * MB + 1)).isInstanceOf(ExportTooLargeException.class);
    }

    @Test
    void nonPositiveLimitIsAConfigurationError() {
        assertThatThrownBy(() -> new ExportSizeLimit(0)).isInstanceOf(IllegalArgumentException.class);
    }
}
