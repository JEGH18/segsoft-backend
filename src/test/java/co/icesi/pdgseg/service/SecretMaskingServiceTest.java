package co.icesi.pdgseg.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class SecretMaskingServiceTest {

    private final SecretMaskingService masking = new SecretMaskingService();

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "api_key=abc123                          | api_key=*****",
            "API-KEY: 'abc123'                       | API-KEY: '*****'",
            "\"apiKey\": \"abc123\"                  | \"apiKey\": \"*****\"",
            "client_secret = abc123                  | client_secret = *****",
            "token=abc123                            | token=*****",
            "password: \"hunter2\"                   | password: \"*****\"",
            "passwd=hunter2                          | passwd=*****",
            "pwd=hunter2                             | pwd=*****",
            "access_key=abc123                       | access_key=*****",
            "credentials=abc123                      | credentials=*****",
            "id: AKIAIOSFODNN7EXAMPLE                | id: *****",
            "t = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 | t = *****",
            // Fake key, split so GitHub push protection does not flag it as real.
            "k = sk_" + "live_51H8xQ2eZvKYlo2C0aBcDe | k = *****",
            "Authorization: Bearer abcdefghijklmnop1234 | Authorization: Bearer *****",
            "jdbc:postgresql://app:s3cr3t@db:5432/x  | jdbc:postgresql://app:*****@db:5432/x",
    })
    void masksKnownSecretShapes(String input, String expected) {
        assertThat(masking.mask(input.strip())).isEqualTo(expected.strip());
    }

    @Test
    void masksPrivateKeyBlocks() {
        String pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----";
        assertThat(masking.mask(pem))
                .isEqualTo("-----BEGIN RSA PRIVATE KEY-----*****-----END RSA PRIVATE KEY-----");
    }

    @Test
    void masksTruncatedPrivateKeyBlocks() {
        assertThat(masking.mask("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B"))
                .doesNotContain("MIIEvQIBADANBgkqhkiG9w0B");
    }

    @Test
    void maskingIsIdempotent() {
        String once = masking.mask("api_key=abc123 password: \"hunter2\" Bearer abcdefghijklmnop1234");
        assertThat(masking.mask(once)).isEqualTo(once);
    }

    @Test
    void keepsThePunctuationAfterAValueTheEngineAlreadyMasked() {
        String engineMasked = "log.info(\"login password=*****, username, password);";
        assertThat(masking.mask(engineMasked)).isEqualTo(engineMasked);
    }

    @Test
    void aSecretGluedToAMaskIsStillMasked() {
        assertThat(masking.mask("password=*****hunter2")).isEqualTo("password=*****");
    }

    @Test
    void leavesOrdinaryCodeUntouched() {
        String code = "String q = \"SELECT * FROM users WHERE id=\" + id; tokenizer.split(passwordField);";
        assertThat(masking.mask(code)).isEqualTo(code);
    }

    @Test
    void nullAndBlankArePassedThrough() {
        assertThat(masking.mask(null)).isNull();
        assertThat(masking.mask("  ")).isEqualTo("  ");
    }
}
