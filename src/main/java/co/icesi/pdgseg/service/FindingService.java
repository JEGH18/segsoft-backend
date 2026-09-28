package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.FindingDetailResponse;
import co.icesi.pdgseg.dto.response.FindingResponse;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Finding;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.repository.FindingRepository;
import co.icesi.pdgseg.repository.spec.FindingSpecifications;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class FindingService {

    // Severity stored as String: alphabetical ASC = CRITICAL, HIGH, LOW, MEDIUM
    // (close enough to severity-descending order without a CASE WHEN expression)
    private static final Sort DEFAULT_SORT = Sort.by(Sort.Direction.ASC, "severity")
            .and(Sort.by(Sort.Direction.ASC, "filePath"));

    private final FindingRepository findingRepository;
    private final SecretMaskingService secretMaskingService;

    public FindingService(FindingRepository findingRepository, SecretMaskingService secretMaskingService) {
        this.findingRepository = findingRepository;
        this.secretMaskingService = secretMaskingService;
    }

    @Transactional(readOnly = true)
    public Page<FindingResponse> getFindings(
            UUID analysisId,
            List<String> severities,
            List<String> categories,
            UUID policyId,
            String filePath,
            Pageable pageable
    ) {
        Specification<Finding> spec = FindingSpecifications.analysisIdEquals(analysisId);

        if (severities != null && !severities.isEmpty()) {
            spec = spec.and(FindingSpecifications.severityIn(parseSeverities(severities)));
        }
        if (categories != null && !categories.isEmpty()) {
            spec = spec.and(FindingSpecifications.categoryIn(categories));
        }
        if (policyId != null) {
            spec = spec.and(FindingSpecifications.policyIdEquals(policyId));
        }
        if (filePath != null && !filePath.isBlank()) {
            spec = spec.and(FindingSpecifications.filePathContains(filePath));
        }

        Pageable sortedPageable = applyDefaultSort(pageable);
        return findingRepository.findAll(spec, sortedPageable).map(this::toFindingResponse);
    }

    @Transactional(readOnly = true)
    public FindingDetailResponse getFindingDetail(UUID findingId) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new ResourceNotFoundException("Finding no encontrado"));

        return new FindingDetailResponse(
                finding.getId(),
                finding.getAnalysis().getId(),
                finding.getPolicy() != null ? finding.getPolicy().getId() : null,
                finding.getPolicy() != null ? finding.getPolicy().getName() : null,
                finding.getPolicy() != null ? finding.getPolicy().getFramework().name() : null,
                finding.getPolicy() != null ? finding.getPolicy().getControlId() : null,
                finding.getCategory(),
                finding.getRule() != null ? finding.getRule().getType() : null,
                finding.getFilePath(),
                finding.getLineNumber(),
                secretMaskingService.mask(finding.getEvidenceSnippet()),
                finding.getCweId(),
                finding.getSeverity(),
                finding.getSuggestedAction()
        );
    }

    @Transactional(readOnly = true)
    public Analysis getAnalysisByFindingId(UUID findingId) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new ResourceNotFoundException("Finding no encontrado"));
        Analysis analysis = finding.getAnalysis();
        // Initialize the lazy proxy within the session so the controller can read
        // id/completedAt (for the ETag) after the transaction closes.
        org.hibernate.Hibernate.initialize(analysis);
        return analysis;
    }

    private Pageable applyDefaultSort(Pageable pageable) {
        if (pageable.getSort().isSorted()) {
            return pageable;
        }
        return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), DEFAULT_SORT);
    }

    private FindingResponse toFindingResponse(Finding finding) {
        return new FindingResponse(
                finding.getId(),
                finding.getPolicy() != null ? finding.getPolicy().getId() : null,
                finding.getPolicy() != null ? finding.getPolicy().getName() : null,
                finding.getRule() != null ? finding.getRule().getId() : null,
                finding.getSeverity(),
                finding.getCategory(),
                finding.getFilePath(),
                finding.getLineNumber(),
                secretMaskingService.mask(finding.getEvidenceSnippet()),
                finding.getFileSha256(),
                finding.getCweId(),
                finding.getSuggestedAction()
        );
    }

    private List<SeverityLevel> parseSeverities(List<String> severities) {
        return severities.stream().map(value -> {
            try {
                return SeverityLevel.valueOf(value.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                throw new UnprocessableEntityException("Severidad inválida: " + value);
            }
        }).toList();
    }
}
