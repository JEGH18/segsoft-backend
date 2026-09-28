package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.NistControlResponse;
import co.icesi.pdgseg.entity.NistControl;
import co.icesi.pdgseg.repository.NistControlRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Escenario 2 de "Incorporar políticas basadas en NIST al catálogo":
 * GET /api/v1/frameworks/nist/controls debe listar controles agrupados por
 * familia (AC, AU, SC, SI...), cada uno con id/title/family.
 */
@ExtendWith(MockitoExtension.class)
class NistControlServiceTest {

    @Mock private NistControlRepository nistControlRepository;

    private NistControlService service;

    @BeforeEach
    void setUp() {
        service = new NistControlService(nistControlRepository);
    }

    private NistControl control(String id, String title, String family) {
        NistControl c = new NistControl();
        ReflectionTestUtils.setField(c, "id", id);
        ReflectionTestUtils.setField(c, "title", title);
        ReflectionTestUtils.setField(c, "family", family);
        return c;
    }

    @Test
    void getControls_noFamilyFilter_returnsAllOrderedByFamily() {
        when(nistControlRepository.findAllByOrderByFamilyAscIdAsc()).thenReturn(List.of(
            control("AC-2", "Account Management", "AC"),
            control("SC-13", "Cryptographic Protection", "SC"),
            control("SI-2", "Flaw Remediation", "SI")
        ));

        List<NistControlResponse> result = service.getControls(null);

        assertThat(result).hasSize(3);
        assertThat(result).extracting(NistControlResponse::id, NistControlResponse::title, NistControlResponse::family)
            .containsExactly(
                org.assertj.core.groups.Tuple.tuple("AC-2", "Account Management", "AC"),
                org.assertj.core.groups.Tuple.tuple("SC-13", "Cryptographic Protection", "SC"),
                org.assertj.core.groups.Tuple.tuple("SI-2", "Flaw Remediation", "SI")
            );
    }

    @Test
    void getControls_filteredByFamily_onlyReturnsThatFamily() {
        when(nistControlRepository.findByFamilyOrderById("SC")).thenReturn(List.of(
            control("SC-8", "Transmission Confidentiality and Integrity", "SC"),
            control("SC-13", "Cryptographic Protection", "SC"),
            control("SC-28", "Protection of Information at Rest", "SC")
        ));

        List<NistControlResponse> result = service.getControls("SC");

        assertThat(result).hasSize(3);
        assertThat(result).allSatisfy(c -> assertThat(c.family()).isEqualTo("SC"));
    }

    @Test
    void getControls_familyFilterIsCaseInsensitive() {
        when(nistControlRepository.findByFamilyOrderById("AU")).thenReturn(List.of(
            control("AU-2", "Event Logging", "AU")
        ));

        List<NistControlResponse> result = service.getControls("au");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).id()).isEqualTo("AU-2");
    }
}
