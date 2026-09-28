package co.icesi.pdgseg.export;

import co.icesi.pdgseg.service.SecretMaskingService;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReportTextSanitizerTest {

    private final ReportTextSanitizer sanitizer = new ReportTextSanitizer(new SecretMaskingService());

    @Test
    void nullBecomesEmpty() {
        assertThat(sanitizer.field(null)).isEmpty();
        assertThat(sanitizer.snippet(null)).isEmpty();
    }

    @Test
    void stripsControlBidiAndZeroWidthCharacters() {
        assertThat(sanitizer.field("src/‮txt.exe\u0007​﻿")).isEqualTo("src/txt.exe");
    }

    @Test
    void fieldsAreSingleLine() {
        assertThat(sanitizer.field("line1\r\nline2\rline3")).isEqualTo("line1 line2 line3");
    }

    @Test
    void snippetsKeepLineBreaksAndExpandTabs() {
        assertThat(sanitizer.snippet("a\r\n\tb")).isEqualTo("a\n    b");
    }

    @Test
    void masksSecretsInEveryKindOfField() {
        assertThat(sanitizer.snippet("password=hunter2")).isEqualTo("password=*****");
        assertThat(sanitizer.field("https://bot:s3cr3t@github.com/acme/app.git"))
                .isEqualTo("https://bot:*****@github.com/acme/app.git");
        assertThat(sanitizer.text("Rotar la clave AKIAIOSFODNN7EXAMPLE")).isEqualTo("Rotar la clave *****");
    }

    @Test
    void zeroWidthCharactersCannotBeUsedToDodgeMasking() {
        assertThat(sanitizer.snippet("pass​word=hunter2")).isEqualTo("password=*****");
    }

    @Test
    void longValuesAreTruncated() {
        String longSnippet = "x".repeat(ReportTextSanitizer.MAX_SNIPPET_LENGTH + 50);
        assertThat(sanitizer.snippet(longSnippet))
                .hasSize(ReportTextSanitizer.MAX_SNIPPET_LENGTH + " […]".length())
                .endsWith(" […]");
    }
}
