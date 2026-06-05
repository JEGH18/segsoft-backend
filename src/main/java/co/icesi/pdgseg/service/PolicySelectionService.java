package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.PolicySelectionRequest;
import co.icesi.pdgseg.dto.response.PolicySelectionResponse;
import co.icesi.pdgseg.dto.response.SelectedPolicySummary;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicySelection;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class PolicySelectionService {

    private static final Logger log = LoggerFactory.getLogger(PolicySelectionService.class);
    private static final List<Category> ALL_CATEGORIES = List.of(
            Category.SQL_INJECTION,
            Category.XSS,
            Category.AUTHENTICATION_FAILURE,
            Category.INSECURE_DATA_HANDLING,
            Category.DEPENDENCY_VULNERABILITY
    );

    private final PolicySelectionRepository policySelectionRepository;
    private final RepositoryRepository repositoryRepository;
    private final PolicyRepository policyRepository;
    private final RuleRepository ruleRepository;
    private final AnalysisRepository analysisRepository;
    private final UserRepository userRepository;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public PolicySelectionService(PolicySelectionRepository policySelectionRepository,
                                  RepositoryRepository repositoryRepository,
                                  PolicyRepository policyRepository,
                                  RuleRepository ruleRepository,
                                  AnalysisRepository analysisRepository,
                                  UserRepository userRepository,
                                  JdbcTemplate jdbcTemplate,
                                  ObjectMapper objectMapper) {
        this.policySelectionRepository = policySelectionRepository;
        this.repositoryRepository = repositoryRepository;
        this.policyRepository = policyRepository;
        this.ruleRepository = ruleRepository;
        this.analysisRepository = analysisRepository;
        this.userRepository = userRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public PolicySelectionResponse createSelection(UUID repoId, PolicySelectionRequest request, String username) {
        Repository repository = getRepositoryOrThrow(repoId);
        ensureNoRunningAnalysis(repoId);
        if (policySelectionRepository.existsByRepositoryId(repoId)) {
            throw new ConflictException("Ya existe una selección de políticas para este repositorio");
        }

        List<Policy> policies = validatePolicies(request.policyIds());
        Map<UUID, Long> rulesByPolicy = getRuleCountByPolicyId(request.policyIds());

        PolicySelection selection = new PolicySelection();
        selection.setRepository(repository);
        selection.setSelectedPolicyIds(new ArrayList<>(request.policyIds()));
        selection.setCreatedBy(findUserByUsername(username));
        selection.setCreatedAt(OffsetDateTime.now());
        selection.setUpdatedAt(OffsetDateTime.now());

        PolicySelection saved = policySelectionRepository.save(selection);
        registerAudit(saved, "CREATED", username, null);
        return toResponse(saved, policies, rulesByPolicy);
    }

    @Transactional
    public PolicySelectionResponse updateSelection(UUID repoId, PolicySelectionRequest request, String username) {
        getRepositoryOrThrow(repoId);
        ensureNoRunningAnalysis(repoId);

        PolicySelection selection = policySelectionRepository.findByRepositoryId(repoId)
                .orElseThrow(() -> new ResourceNotFoundException("No existe selección de políticas para el repositorio"));

        List<Policy> policies = validatePolicies(request.policyIds());
        Map<UUID, Long> rulesByPolicy = getRuleCountByPolicyId(request.policyIds());

        selection.setSelectedPolicyIds(new ArrayList<>(request.policyIds()));
        selection.setUpdatedAt(OffsetDateTime.now());
        PolicySelection saved = policySelectionRepository.save(selection);
        registerAudit(saved, "UPDATED", username, null);

        return toResponse(saved, policies, rulesByPolicy);
    }

    @Transactional(readOnly = true)
    public PolicySelectionResponse getSelection(UUID repoId) {
        getRepositoryOrThrow(repoId);
        PolicySelection selection = policySelectionRepository.findByRepositoryId(repoId)
                .orElseThrow(() -> new ResourceNotFoundException("No existe selección de políticas para el repositorio"));

        List<Policy> policies = policyRepository.findByIdIn(selection.getSelectedPolicyIds());
        Map<UUID, Long> rulesByPolicy = getRuleCountByPolicyId(selection.getSelectedPolicyIds());
        return toResponse(selection, policies, rulesByPolicy);
    }

    @Transactional
    public void deleteSelection(UUID repoId) {
        getRepositoryOrThrow(repoId);
        ensureNoRunningAnalysis(repoId);
        PolicySelection selection = policySelectionRepository.findByRepositoryId(repoId)
                .orElseThrow(() -> new ResourceNotFoundException("No existe selección de políticas para el repositorio"));
        policySelectionRepository.delete(selection);
    }

    private Repository getRepositoryOrThrow(UUID repoId) {
        return repositoryRepository.findById(repoId)
                .orElseThrow(() -> new ResourceNotFoundException("Repositorio no encontrado"));
    }

    private List<Policy> validatePolicies(List<UUID> policyIds) {
        ensureNoDuplicates(policyIds);
        if (policyIds == null || policyIds.isEmpty()) {
            throw new BusinessValidationException("Debe seleccionar al menos una política");
        }

        List<Policy> policies = policyRepository.findByIdIn(policyIds);
        Set<UUID> foundIds = policies.stream().map(Policy::getId).collect(Collectors.toSet());
        List<UUID> missingIds = policyIds.stream().filter(id -> !foundIds.contains(id)).toList();
        if (!missingIds.isEmpty()) {
            throw new BusinessValidationException("Existen políticas que no fueron encontradas");
        }

        List<UUID> inactivePolicies = policies.stream()
                .filter(policy -> policy.getStatus() != PolicyStatus.ACTIVE)
                .map(Policy::getId)
                .toList();
        if (!inactivePolicies.isEmpty()) {
            throw new BusinessValidationException("Todas las políticas deben estar ACTIVE");
        }

        Map<UUID, Long> rulesByPolicy = getRuleCountByPolicyId(policyIds);
        List<UUID> nonExecutable = policyIds.stream()
                .filter(policyId -> rulesByPolicy.getOrDefault(policyId, 0L) == 0L)
                .toList();
        if (!nonExecutable.isEmpty()) {
            throw new BusinessValidationException("Todas las políticas deben tener al menos una regla técnica");
        }

        return policies;
    }

    private Map<UUID, Long> getRuleCountByPolicyId(List<UUID> policyIds) {
        if (policyIds == null || policyIds.isEmpty()) {
            return Map.of();
        }
        return ruleRepository.countEnabledRulesByPolicyIds(policyIds).stream()
                .collect(Collectors.toMap(
                        PolicyRuleCountProjection::getPolicyId,
                        PolicyRuleCountProjection::getRulesCount
                ));
    }

    private void ensureNoDuplicates(List<UUID> policyIds) {
        if (policyIds == null) {
            return;
        }
        Set<UUID> distinct = new HashSet<>(policyIds);
        if (distinct.size() != policyIds.size()) {
            throw new BusinessValidationException("No se permiten UUIDs duplicados en policyIds");
        }
    }

    private void ensureNoRunningAnalysis(UUID repoId) {
        boolean hasRunning = analysisRepository.existsByRepositoryIdAndStatusIn(
                repoId,
                List.of(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING)
        );
        if (hasRunning) {
            throw new ConflictException("No se puede modificar la selección mientras exista un análisis en curso");
        }
    }

    private PolicySelectionResponse toResponse(PolicySelection selection,
                                               List<Policy> policies,
                                               Map<UUID, Long> rulesByPolicy) {
        Map<UUID, Policy> policiesById = policies.stream()
                .collect(Collectors.toMap(Policy::getId, Function.identity()));

        List<SelectedPolicySummary> selectedPolicies = selection.getSelectedPolicyIds().stream()
                .map(policiesById::get)
                .filter(Objects::nonNull)
                .map(policy -> new SelectedPolicySummary(
                        policy.getId(),
                        policy.getName(),
                        policy.getFramework(),
                        policy.getControlId(),
                        policy.getCategory(),
                        rulesByPolicy.getOrDefault(policy.getId(), 0L)
                ))
                .toList();

        Map<Category, Long> categoryCoverage = ALL_CATEGORIES.stream()
                .collect(Collectors.toMap(
                        Function.identity(),
                        category -> selectedPolicies.stream()
                                .filter(summary -> summary.category() == category)
                                .count(),
                        (left, right) -> left,
                        LinkedHashMap::new
                ));

        List<Category> uncovered = categoryCoverage.entrySet().stream()
                .filter(entry -> entry.getValue() == 0L)
                .map(Map.Entry::getKey)
                .toList();

        return new PolicySelectionResponse(
                selection.getId(),
                selection.getRepository().getId(),
                selectedPolicies,
                categoryCoverage,
                uncovered,
                selection.getVersion()
        );
    }

    private User findUserByUsername(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }
        return userRepository.findByUsername(username).orElse(null);
    }

    private void registerAudit(PolicySelection selection,
                               String action,
                               String username,
                               UUID userId) {
        try {
            String payload = objectMapper.writeValueAsString(Map.of(
                    "selectionId", selection.getId(),
                    "policyIds", selection.getSelectedPolicyIds(),
                    "version", selection.getVersion()
            ));
            jdbcTemplate.update(
                    "INSERT INTO selection_audit_log (repository_id, action, user_id, username, payload) " +
                            "VALUES (?, ?, ?, ?, ?::jsonb)",
                    selection.getRepository().getId(),
                    action,
                    userId,
                    username,
                    payload
            );
        } catch (JsonProcessingException | org.springframework.dao.DataAccessException e) {
            log.error("Failed to persist selection audit action={} repoId={}", action, selection.getRepository().getId(), e);
        }
    }
}
