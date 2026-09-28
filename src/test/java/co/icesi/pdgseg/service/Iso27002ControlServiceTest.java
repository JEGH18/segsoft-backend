package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.Iso27002ControlResponse;
import co.icesi.pdgseg.entity.Iso27002Control;
import co.icesi.pdgseg.entity.enums.Iso27002Category;
import co.icesi.pdgseg.repository.Iso27002ControlRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Escenario 2 de "Derivar políticas del catálogo a partir de ISO/IEC
 * 27002": GET /api/v1/frameworks/iso-27002/controls debe listar el catálogo
 * agrupado en las 4 categorías temáticas, cada control con
 * id/title/category/implementationGuidance; filtrable por categoría y/o
 * por control de ISO/IEC 27001 relacionado.
 */
@ExtendWith(MockitoExtension.class)
class Iso27002ControlServiceTest {

    @Mock private Iso27002ControlRepository iso27002ControlRepository;

    private Iso27002ControlService service;

    @BeforeEach
    void setUp() {
        service = new Iso27002ControlService(iso27002ControlRepository);
    }

    private Iso27002Control control(String id, String title, Iso27002Category category, String annexA) {
        Iso27002Control c = new Iso27002Control();
        ReflectionTestUtils.setField(c, "id", id);
        ReflectionTestUtils.setField(c, "title", title);
        ReflectionTestUtils.setField(c, "category", category);
        ReflectionTestUtils.setField(c, "implementationGuidance", "Guía de prueba para " + title);
        ReflectionTestUtils.setField(c, "correspondingAnnexAControl", annexA);
        return c;
    }

    @Test
    void getControls_noFilters_returnsFullCatalogWithAllFields() {
        when(iso27002ControlRepository.findAllByOrderByCategoryAscIdAsc()).thenReturn(List.of(
            control("5.1", "Policies for information security", Iso27002Category.ORGANIZATIONAL, "A.5.1"),
            control("8.24", "Use of cryptography", Iso27002Category.TECHNOLOGICAL, "A.8.24")
        ));

        List<Iso27002ControlResponse> result = service.getControls(null, null);

        assertThat(result).hasSize(2);
        assertThat(result.get(1).id()).isEqualTo("8.24");
        assertThat(result.get(1).title()).isEqualTo("Use of cryptography");
        assertThat(result.get(1).category()).isEqualTo("TECHNOLOGICAL");
        assertThat(result.get(1).implementationGuidance()).isNotBlank();
    }

    @Test
    void getControls_filteredByCategory_onlyReturnsThatCategory() {
        when(iso27002ControlRepository.findByCategoryOrderById(Iso27002Category.TECHNOLOGICAL)).thenReturn(List.of(
            control("8.5", "Secure authentication", Iso27002Category.TECHNOLOGICAL, "A.8.5"),
            control("8.24", "Use of cryptography", Iso27002Category.TECHNOLOGICAL, "A.8.24")
        ));

        List<Iso27002ControlResponse> result = service.getControls(Iso27002Category.TECHNOLOGICAL, null);

        assertThat(result).hasSize(2);
        assertThat(result).allSatisfy(c -> assertThat(c.category()).isEqualTo("TECHNOLOGICAL"));
    }

    @Test
    void getControls_filteredByRelatedAnnexAControl() {
        when(iso27002ControlRepository.findByCorrespondingAnnexAControlOrderById("A.8.24")).thenReturn(List.of(
            control("8.24", "Use of cryptography", Iso27002Category.TECHNOLOGICAL, "A.8.24")
        ));

        List<Iso27002ControlResponse> result = service.getControls(null, "A.8.24");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).id()).isEqualTo("8.24");
    }

    @Test
    void findById_existingControl_returnsIt() {
        when(iso27002ControlRepository.findById("8.24"))
            .thenReturn(Optional.of(control("8.24", "Use of cryptography", Iso27002Category.TECHNOLOGICAL, "A.8.24")));

        Optional<Iso27002Control> result = service.findById("8.24");

        assertThat(result).isPresent();
        assertThat(result.get().getCorrespondingAnnexAControl()).isEqualTo("A.8.24");
    }
}
