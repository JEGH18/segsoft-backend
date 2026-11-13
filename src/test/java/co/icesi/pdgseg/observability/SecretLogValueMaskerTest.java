package co.icesi.pdgseg.observability;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Masking of the string values of a log line (logback-spring.xml). */
class SecretLogValueMaskerTest {

    private final SecretLogValueMasker masker = new SecretLogValueMasker();

    private String masked(String value) {
        Object result = masker.mask(null, value);
        return result != null ? result.toString() : value;
    }

    @Test
    void masksTheAuthorizationHeaderWhateverTheTokenIs() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ";
        assertThat(masked("headers=[Authorization:\"Bearer " + jwt + "\"]")).doesNotContain(jwt).contains("Bearer *****");
        String apiToken = "pdgseg_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCd";
        assertThat(masked("Authorization: Bearer " + apiToken)).doesNotContain(apiToken);
        assertThat(masked("token de CI " + apiToken + " usado")).doesNotContain(apiToken);
    }

    @Test
    void masksPasswordsAndSecretsInMessagesAndStackTraces() {
        assertThat(masked("login password=Sup3rS3creta! fallido")).doesNotContain("Sup3rS3creta!");
        assertThat(masked("java.lang.IllegalStateException: api_key: \"AKIA1234567890ABCDEF\"\n\tat co.icesi.X"))
                .doesNotContain("AKIA1234567890ABCDEF");
        assertThat(masked("jdbc:postgresql://segsoft:clave-db@postgres:5432/segsoft")).doesNotContain("clave-db");
    }

    @Test
    void leavesOrdinaryValuesAndNonStringsAlone() {
        assertThat(masker.mask(null, "Análisis completado analysisId=42 duracionMs=120")).isNull();
        assertThat(masker.mask(null, "6f1c2a8e-3f0b-4a59-9d6e-0c2b7d1e4f5a")).isNull();
        assertThat(masker.mask(null, 42)).isNull();
    }
}
