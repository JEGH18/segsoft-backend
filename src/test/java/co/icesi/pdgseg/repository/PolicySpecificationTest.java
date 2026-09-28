package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.enums.PolicyStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PolicySpecificationTest {

    @Test
    void withStatus_null_addsNoPredicate_soEveryStatusMatches() {
        // No status chosen ("Todos los estados" in the UI) must mean literally
        // no filtering -- active, archived and deprecated all come back mixed.
        assertThat(PolicySpecification.withStatus(null).toPredicate(null, null, null)).isNull();
    }

    @Test
    void withStatus_explicitValue_isARealFilteringSpecification() {
        assertThat(PolicySpecification.withStatus(PolicyStatus.ACTIVE)).isNotNull();
    }
}
