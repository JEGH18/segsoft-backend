package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.NistControlResponse;
import co.icesi.pdgseg.entity.NistControl;
import co.icesi.pdgseg.repository.NistControlRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NistControlService {

    private final NistControlRepository nistControlRepository;

    public NistControlService(NistControlRepository nistControlRepository) {
        this.nistControlRepository = nistControlRepository;
    }

    /** Escenario 2: listado ordenado por familia (AC, AU, IA, SC, SI...), filtrable por familia. */
    public List<NistControlResponse> getControls(String family) {
        List<NistControl> controls = (family == null || family.isBlank())
            ? nistControlRepository.findAllByOrderByFamilyAscIdAsc()
            : nistControlRepository.findByFamilyOrderById(family.toUpperCase());
        return controls.stream()
            .map(c -> new NistControlResponse(c.getId(), c.getTitle(), c.getFamily()))
            .toList();
    }
}
