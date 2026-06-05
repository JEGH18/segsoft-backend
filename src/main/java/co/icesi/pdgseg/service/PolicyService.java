package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreatePolicyRequest;
import co.icesi.pdgseg.dto.response.CategoryCoverageItem;
import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.entity.enums.RuleStatus;
import co.icesi.pdgseg.exception.PolicyConflictException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.PolicySpecification;
import co.icesi.pdgseg.repository.RuleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class PolicyService {

    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);

    private final PolicyRepository policyRepository;
    private final UserRepository userRepository;
    private final RuleRepository ruleRepository;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public PolicyService(PolicyRepository policyRepository,
                         UserRepository userRepository,
                         RuleRepository ruleRepository,
                         JdbcTemplate jdbcTemplate,
                         ObjectMapper objectMapper) {
        this.policyRepository = policyRepository;
        this.userRepository = userRepository;
        this.ruleRepository = ruleRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public Page<PolicyResponse> search(Framework framework, Category category,
                                        PolicyStatus status, String name, Pageable pageable) {
        Specification<Policy> spec = Specification
            .where(PolicySpecification.withFramework(framework))
            .and(PolicySpecification.withCategory(category))
            .and(PolicySpecification.withStatus(status))
            .and(PolicySpecification.withNameContaining(name));

        Page<Policy> page = policyRepository.findAll(spec, pageable);

        // Fetch rule counts in one batch query
        List<UUID> policyIds = page.stream().map(Policy::getId).collect(Collectors.toList());
        Map<UUID, Long> countMap = buildCountMap(policyIds);

        return page.map(p -> {
            long count = countMap.getOrDefault(p.getId(), 0L);
            return toResponse(p, (int) count, count > 0);
        });
    }

    public PolicyResponse findById(UUID id) {
        Policy p = policyRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException(
                "Política no encontrada con id: " + id));
        int count = ruleRepository.countByPolicyAndStatus(p, RuleStatus.ACTIVE);
        return toResponse(p, count, count > 0);
    }

    public List<CategoryCoverageItem> getCoverage() {
        List<CategoryCoverageItem> result = new ArrayList<>();
        for (Category category : Category.values()) {
            Specification<Policy> spec = Specification
                .where(PolicySpecification.withCategory(category))
                .and(PolicySpecification.withStatus(PolicyStatus.ACTIVE));
            List<Policy> policies = policyRepository.findAll(spec);
            int activePolicies = policies.size();

            List<UUID> ids = policies.stream().map(Policy::getId).collect(Collectors.toList());
            Map<UUID, Long> countMap = buildCountMap(ids);
            int executablePolicies = (int) countMap.values().stream().filter(c -> c > 0).count();

            result.add(new CategoryCoverageItem(category.name(), activePolicies, executablePolicies));
        }
        return result;
    }

    private Map<UUID, Long> buildCountMap(List<UUID> policyIds) {
        if (policyIds.isEmpty()) return Map.of();
        List<Object[]> rows = ruleRepository.countActiveByPolicyIds(policyIds);
        Map<UUID, Long> map = new HashMap<>();
        for (Object[] row : rows) {
            map.put((UUID) row[0], (Long) row[1]);
        }
        return map;
    }

    @Transactional
    public PolicyResponse create(CreatePolicyRequest request, String username) {
        if (policyRepository.existsByNameAndFramework(request.name(), request.framework())) {
            throw new PolicyConflictException(
                "Ya existe una política con el nombre '" + request.name() +
                "' y el marco '" + request.framework() + "'");
        }

        User creator = userRepository.findByUsername(username).orElseThrow(
            () -> new IllegalStateException("Usuario autenticado no encontrado: " + username)
        );

        Policy policy = new Policy();
        policy.setName(request.name());
        policy.setDescription(request.description());
        policy.setCategory(request.category());
        policy.setFramework(request.framework());
        policy.setControlId(request.controlId());
        policy.setStatus(PolicyStatus.ACTIVE);
        policy.setVersion(1);
        policy.setWeight(50);
        policy.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        policy.setCreatedBy(creator);

        Policy saved = policyRepository.saveAndFlush(policy);

        registrarAuditoria("POLICY_CREATED", username, saved.getId(),
            Map.of(
                "name", saved.getName(),
                "category", saved.getCategory().name(),
                "framework", saved.getFramework().name()
            ));

        return toResponse(saved);
    }

    private void registrarAuditoria(String action, String username, UUID policyId,
                                    Map<String, Object> payload) {
        try {
            String payloadJson = objectMapper.writeValueAsString(payload);
            jdbcTemplate.update(
                "INSERT INTO policy_audit_log (action, policy_id, username, payload) " +
                "VALUES (?, ?, ?, ?::jsonb)",
                action, policyId, username, payloadJson
            );
        } catch (JsonProcessingException | org.springframework.dao.DataAccessException e) {
            log.error("No se pudo registrar auditoría de política action={} policy={}",
                action, policyId, e);
        }
    }

    public static PolicyResponse toResponse(Policy p) {
        return toResponse(p, 0, false);
    }

    public static PolicyResponse toResponse(Policy p, int rulesCount, boolean executable) {
        UUID createdById = p.getCreatedBy() != null ? p.getCreatedBy().getId() : null;
        return new PolicyResponse(
            p.getId(),
            p.getName(),
            p.getDescription(),
            p.getCategory(),
            p.getFramework(),
            p.getControlId(),
            p.getStatus(),
            p.getVersion(),
            p.getWeight(),
            p.getCreatedAt(),
            createdById,
            executable,
            rulesCount
        );
    }
}
