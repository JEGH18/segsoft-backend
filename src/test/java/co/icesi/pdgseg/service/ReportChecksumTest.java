package co.icesi.pdgseg.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReportChecksumTest {

    private static final String ORIGINAL =
            "{\"schemaVersion\":3,\"metadata\":{\"repositoryName\":\"acme\",\"generatedBy\":\"auditor\"},"
                    + "\"summary\":{\"compliancePercentage\":91.30,\"totalFindings\":2},\"findings\":[{\"snippet\":\"ñ <x>\"}]}";

    /** The same value as PostgreSQL's JSONB returns it: keys reordered, spaces added. */
    private static final String AS_JSONB =
            "{\"summary\": {\"totalFindings\": 2, \"compliancePercentage\": 91.30}, \"findings\": [{\"snippet\": \"ñ <x>\"}], "
                    + "\"metadata\": {\"generatedBy\": \"auditor\", \"repositoryName\": \"acme\"}, \"schemaVersion\": 3}";

    @Test
    void isIndependentOfKeyOrderAndWhitespaceSoItSurvivesJsonb() {
        assertThat(ReportChecksum.of(AS_JSONB)).isEqualTo(ReportChecksum.of(ORIGINAL));
    }

    @Test
    void isIndependentOfRedundantNumberFormatting() {
        assertThat(ReportChecksum.of("{\"p\":91.3}")).isEqualTo(ReportChecksum.of("{\"p\":91.30}"));
        assertThat(ReportChecksum.of("{\"p\":0}")).isEqualTo(ReportChecksum.of("{\"p\":0.00}"));
        assertThat(ReportChecksum.of("{\"p\":100}")).isEqualTo(ReportChecksum.of("{\"p\":1.0E2}"));
    }

    @Test
    void detectsAnyChangeOfValue() {
        assertThat(ReportChecksum.of(ORIGINAL.replace("91.30", "95.30"))).isNotEqualTo(ReportChecksum.of(ORIGINAL));
        assertThat(ReportChecksum.of(ORIGINAL.replace("auditor", "admin"))).isNotEqualTo(ReportChecksum.of(ORIGINAL));
        assertThat(ReportChecksum.of(ORIGINAL.replace("\"totalFindings\":2", "\"totalFindings\":\"2\"")))
                .isNotEqualTo(ReportChecksum.of(ORIGINAL));
    }

    @Test
    void arrayOrderIsSignificant() {
        assertThat(ReportChecksum.of("{\"a\":[1,2]}")).isNotEqualTo(ReportChecksum.of("{\"a\":[2,1]}"));
    }

    @Test
    void canonicalFormIsCompactSortedJson() {
        assertThat(ReportChecksum.canonical(AS_JSONB)).isEqualTo(
                "{\"findings\":[{\"snippet\":\"ñ <x>\"}],\"metadata\":{\"generatedBy\":\"auditor\",\"repositoryName\":\"acme\"},"
                        + "\"schemaVersion\":3,\"summary\":{\"compliancePercentage\":91.3,\"totalFindings\":2}}");
    }

    /**
     * Golden value, computed independently (Python hashlib over the canonical
     * string). Every stored checksum depends on this canonical form: if this
     * test fails, existing reports would stop verifying. Do not "update" the
     * expected value without a migration that re-seals them.
     */
    @Test
    void formatIsFrozen() {
        assertThat(ReportChecksum.of(ORIGINAL)).isEqualTo("942e0d8daf9ecb641bc9c15a472779dd9b0decb1fa0dea83b0649130d361b815");
    }

    @Test
    void rejectsInvalidJson() {
        assertThatThrownBy(() -> ReportChecksum.of("{\"a\":")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ReportChecksum.of("{\"a\":1} {\"b\":2}")).isInstanceOf(IllegalArgumentException.class);
    }
}
