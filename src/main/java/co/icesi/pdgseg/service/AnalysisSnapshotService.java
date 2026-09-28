package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.snapshot.AnalysisSnapshotDto;
import co.icesi.pdgseg.dto.snapshot.PolicySnapshotDto;
import co.icesi.pdgseg.dto.snapshot.RuleSnapshotDto;
import co.icesi.pdgseg.entity.*;
import co.icesi.pdgseg.entity.enums.RuleStatus;
import co.icesi.pdgseg.exception.UnprocessableEntityException;
import co.icesi.pdgseg.repository.AnalysisSnapshotRepository;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class AnalysisSnapshotService {

    private final AnalysisSnapshotRepository analysisSnapshotRepository;
    private final PolicyRepository policyRepository;
    private final RuleRepository ruleRepository;
    private final ObjectMapper objectMapper;

    public AnalysisSnapshotService(
            AnalysisSnapshotRepository analysisSnapshotRepository,
            PolicyRepository policyRepository,
            RuleRepository ruleRepository,
            ObjectMapper objectMapper
    ) {
        this.analysisSnapshotRepository = analysisSnapshotRepository;
        this.policyRepository = policyRepository;
        this.ruleRepository = ruleRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public AnalysisSnapshotDto createSnapshot(Analysis analysis, PolicySelection policySelection) {
        List<UUID> selectedPolicyIds = policySelection.getSelectedPolicyIds();
        if (selectedPolicyIds == null || selectedPolicyIds.isEmpty()) {
            throw new UnprocessableEntityException("El repositorio no tiene políticas seleccionadas");
        }

        List<Policy> policies = policyRepository.findByIdIn(selectedPolicyIds);
        List<Rule> rules = ruleRepository.findByPolicyIdInAndStatus(selectedPolicyIds, RuleStatus.ACTIVE);
        Map<UUID, List<RuleSnapshotDto>> rulesByPolicy = new HashMap<>();

        for (Rule rule : rules) {
            RuleSnapshotDto ruleSnapshot = new RuleSnapshotDto(
                    rule.getId(),
                    rule.getType().name(),
                    rule.getSeverity().name(),
                    rule.getCategory(),
                    rule.getPayload() != null ? rule.getPayload() : Map.of()
            );
            rulesByPolicy.computeIfAbsent(rule.getPolicy().getId(), key -> new ArrayList<>()).add(ruleSnapshot);
        }

        List<PolicySnapshotDto> policySnapshots = new ArrayList<>();
        for (Policy policy : policies) {
            policySnapshots.add(new PolicySnapshotDto(
                    policy.getId(),
                    policy.getName(),
                    policy.getCategory() != null ? policy.getCategory().name() : null,
                    rulesByPolicy.getOrDefault(policy.getId(), List.of())
            ));
        }

        AnalysisSnapshotDto snapshotDto = new AnalysisSnapshotDto(policySnapshots);

        AnalysisSnapshot snapshot = new AnalysisSnapshot();
        snapshot.setAnalysis(analysis);
        snapshot.setSnapshotJson(serialize(snapshotDto));
        analysisSnapshotRepository.save(snapshot);

        return snapshotDto;
    }

    @Transactional(readOnly = true)
    public AnalysisSnapshotDto getSnapshot(UUID analysisId) {
        AnalysisSnapshot snapshot = analysisSnapshotRepository.findByAnalysisId(analysisId)
                .orElseThrow(() -> new IllegalStateException("Snapshot no encontrado para el análisis"));
        try {
            return objectMapper.readValue(snapshot.getSnapshotJson(), AnalysisSnapshotDto.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Snapshot inválido para el análisis", e);
        }
    }

    private String serialize(AnalysisSnapshotDto snapshotDto) {
        try {
            return objectMapper.writeValueAsString(snapshotDto);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("No se pudo serializar snapshot", e);
        }
    }

}
