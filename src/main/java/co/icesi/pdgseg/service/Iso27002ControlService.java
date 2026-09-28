package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.Iso27002ControlResponse;
import co.icesi.pdgseg.entity.Iso27002Control;
import co.icesi.pdgseg.entity.enums.Iso27002Category;
import co.icesi.pdgseg.repository.Iso27002ControlRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class Iso27002ControlService {

    private final Iso27002ControlRepository iso27002ControlRepository;

    public Iso27002ControlService(Iso27002ControlRepository iso27002ControlRepository) {
        this.iso27002ControlRepository = iso27002ControlRepository;
    }

    /** Escenario 2: catálogo completo agrupado por categoría temática, filtrable por categoría y/o control 27001 relacionado. */
    public List<Iso27002ControlResponse> getControls(Iso27002Category category, String relatedAnnexAControl) {
        List<Iso27002Control> controls;
        if (category != null && relatedAnnexAControl != null) {
            controls = iso27002ControlRepository.findByCategoryAndCorrespondingAnnexAControlOrderById(
                category, relatedAnnexAControl);
        } else if (category != null) {
            controls = iso27002ControlRepository.findByCategoryOrderById(category);
        } else if (relatedAnnexAControl != null) {
            controls = iso27002ControlRepository.findByCorrespondingAnnexAControlOrderById(relatedAnnexAControl);
        } else {
            controls = iso27002ControlRepository.findAllByOrderByCategoryAscIdAsc();
        }
        return controls.stream()
            .map(c -> new Iso27002ControlResponse(c.getId(), c.getTitle(), c.getCategory().name(), c.getImplementationGuidance()))
            .toList();
    }

    /** Escenario 3: valida que el implementationGuideId elegido corresponda al controlId de ISO/IEC 27001 dado. */
    public Optional<Iso27002Control> findById(String id) {
        return iso27002ControlRepository.findById(id);
    }
}
