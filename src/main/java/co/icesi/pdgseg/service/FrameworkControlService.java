package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.FrameworkControlResponse;
import co.icesi.pdgseg.entity.FrameworkControl;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.repository.FrameworkControlRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class FrameworkControlService {

    private final FrameworkControlRepository frameworkControlRepository;

    public FrameworkControlService(FrameworkControlRepository frameworkControlRepository) {
        this.frameworkControlRepository = frameworkControlRepository;
    }

    public List<FrameworkControlResponse> getControlsFor(Framework framework) {
        return frameworkControlRepository.findByFrameworkOrderByCategory(framework).stream()
            .map(fc -> new FrameworkControlResponse(fc.getCategory().name(), fc.getControlId(), fc.getControlName()))
            .toList();
    }

    public Optional<FrameworkControl> findControl(Framework framework, Category category) {
        return frameworkControlRepository.findByFrameworkAndCategory(framework, category);
    }
}
