package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreatePolicySetRequest;
import co.icesi.pdgseg.dto.request.UpdatePolicySetRequest;
import co.icesi.pdgseg.dto.response.PolicyAuditLogEntryResponse;
import co.icesi.pdgseg.dto.response.PolicySetDetailResponse;
import co.icesi.pdgseg.dto.response.PolicySetPageResponse;
import co.icesi.pdgseg.dto.response.PolicySetPolicySummary;
import co.icesi.pdgseg.dto.response.PolicySetResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicySet;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.PolicySetStatus;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.PolicySelectionRepository;
import co.icesi.pdgseg.repository.PolicySetRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class PolicySetService {

    private static final Logger log = LoggerFactory.getLogger(PolicySetService.class);

    private static final List<AnalysisStatus> IN_FLIGHT_STATUSES = List.of(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING);

    private final PolicySetRepository policySetRepository;
    private final PolicyRepository policyRepository;
    private final PolicySelectionRepository policySelectionRepository;
    private final AnalysisRepository analysisRepository;
    private final UserRepository userRepository;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public PolicySetService(PolicySetRepository policySetRepository,
                             PolicyRepository policyRepository,
                             PolicySelectionRepository policySelectionRepository,
                             AnalysisRepository analysisRepository,
                             UserRepository userRepository,
                             JdbcTemplate jdbcTemplate,
                             ObjectMapper objectMapper) {
        this.policySetRepository = policySetRepository;
        this.policyRepository = policyRepository;
        this.policySelectionRepository = policySelectionRepository;
        this.analysisRepository = analysisRepository;
        this.userRepository = userRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    /** Escenario 1 / 3 / 4 / 5: paginado, filtrable por status (default ACTIVE) y por nombre. */
    @Transactional(readOnly = true)
    public PolicySetPageResponse list(PolicySetStatus status, String search, Pageable pageable) {
        PolicySetStatus effectiveStatus = status != null ? status : PolicySetStatus.ACTIVE;
        String effectiveSearch = search != null ? search : "";

        Page<PolicySet> page = policySetRepository.findByStatusAndNameContainingIgnoreCase(
            effectiveStatus, effectiveSearch, pageable);

        String message = policySetRepository.count() == 0
            ? "No hay Policy Sets registrados. Cree uno para estandarizar sus análisis."
            : null;

        return new PolicySetPageResponse(
            page.getContent().stream().map(this::toResponse).collect(Collectors.toList()),
            page.getNumber(),
            page.getSize(),
            page.getTotalElements(),
            page.getTotalPages(),
            message
        );
    }

    @Transactional(readOnly = true)
    public PolicySetResponse findById(UUID id) {
        return toResponse(getOrThrow(id));
    }

    /** Escenario 2: políticas incluidas (id/name/framework/category), cobertura por categoría y usageCount. */
    @Transactional(readOnly = true)
    public PolicySetDetailResponse findDetailById(UUID id) {
        PolicySet ps = getOrThrow(id);
        List<Policy> policies = new ArrayList<>(ps.getPolicies());

        List<PolicySetPolicySummary> policySummaries = policies.stream()
            .map(p -> new PolicySetPolicySummary(p.getId(), p.getName(), p.getFramework(), p.getCategory()))
            .collect(Collectors.toList());

        Map<Category, Long> categoryCoverage = Arrays.stream(Category.values())
            .collect(Collectors.toMap(
                Function.identity(),
                category -> policies.stream().filter(p -> p.getCategory() == category).count(),
                (left, right) -> left,
                LinkedHashMap::new
            ));

        int usageCount = policySelectionRepository.findRepositoryIdsByPolicySetId(id).size();

        return new PolicySetDetailResponse(
            ps.getId(),
            ps.getName(),
            ps.getDescription(),
            ps.getStatus(),
            ps.getVersion(),
            policies.stream().map(Policy::getId).collect(Collectors.toList()),
            policies.stream().map(Policy::getName).collect(Collectors.toList()),
            policySummaries,
            categoryCoverage,
            usageCount,
            ps.getCreatedAt(),
            ps.getCreatedBy() != null ? ps.getCreatedBy().getId() : null,
            ps.getUpdatedAt()
        );
    }

    /** Escenario 1 / 2: cada policyId debe existir y estar ACTIVE, o se rechaza con 400. */
    @Transactional
    public PolicySetResponse create(CreatePolicySetRequest request, String username) {
        List<Policy> policies = resolveActivePolicies(request.policyIds());

        User creator = userRepository.findByUsername(username).orElseThrow(
            () -> new IllegalStateException("Usuario autenticado no encontrado: " + username));

        PolicySet policySet = new PolicySet();
        policySet.setName(request.name());
        policySet.setDescription(request.description());
        policySet.setStatus(PolicySetStatus.ACTIVE);
        policySet.setVersion(1);
        policySet.setPolicies(new LinkedHashSet<>(policies));
        policySet.setCreatedBy(creator);

        PolicySet saved = policySetRepository.saveAndFlush(policySet);

        registrarAuditoria("POLICY_SET_CREATED", username, saved.getId(),
            Map.of("name", saved.getName(), "policyIds", request.policyIds()));

        return toResponse(saved);
    }

    /** Escenario 3: composición editable, versión +1, diff auditado; no retroactivo por diseño (ver nota abajo). */
    @Transactional
    public PolicySetResponse patch(UUID id, UpdatePolicySetRequest request, String username) {
        PolicySet policySet = getOrThrow(id);

        if (policySet.getStatus() != PolicySetStatus.ACTIVE) {
            throw new BusinessValidationException("Solo se pueden editar Policy Sets en estado ACTIVE");
        }

        Map<String, Object> diff = new LinkedHashMap<>();

        if (request.name() != null && !request.name().equals(policySet.getName())) {
            diff.put("name", Map.of("from", String.valueOf(policySet.getName()), "to", request.name()));
        }
        if (request.description() != null && !request.description().equals(policySet.getDescription())) {
            diff.put("description", Map.of(
                "from", String.valueOf(policySet.getDescription()),
                "to", request.description()));
        }

        Set<Policy> newPolicies = null;
        if (request.policyIds() != null) {
            List<Policy> resolved = resolveActivePolicies(request.policyIds());
            Set<UUID> currentIds = policySet.getPolicies().stream().map(Policy::getId).collect(Collectors.toSet());
            Set<UUID> requestedIds = new LinkedHashSet<>(request.policyIds());

            List<UUID> added = requestedIds.stream().filter(pid -> !currentIds.contains(pid)).toList();
            List<UUID> removed = currentIds.stream().filter(pid -> !requestedIds.contains(pid)).toList();

            if (!added.isEmpty() || !removed.isEmpty()) {
                diff.put("policies", Map.of("added", added, "removed", removed));
                newPolicies = new LinkedHashSet<>(resolved);
            }
        }

        if (diff.isEmpty()) {
            return toResponse(policySet);
        }

        if (request.name() != null) policySet.setName(request.name());
        if (request.description() != null) policySet.setDescription(request.description());
        if (newPolicies != null) policySet.setPolicies(newPolicies);

        // Manual bump (not JPA @Version): deterministic "+1 per edit" that
        // doesn't depend on whether Hibernate treats a @ManyToMany-only
        // change as dirtying the owning entity. Repositorios donde el set ya
        // se aplicó (PolicySelection.selectedPolicyIds) guardan una copia
        // independiente de los ids en el momento de aplicarlo -- por eso
        // editar el Policy Set después no los toca retroactivamente.
        policySet.setVersion(policySet.getVersion() + 1);
        policySet.setUpdatedAt(OffsetDateTime.now());

        PolicySet saved = policySetRepository.saveAndFlush(policySet);

        registrarAuditoria("POLICY_SET_UPDATED", username, saved.getId(), diff);

        return toResponse(saved);
    }

    /** Escenario 4 / 5: archivado lógico, bloqueado por HTTP 409 si hay análisis en curso. */
    @Transactional
    public void archive(UUID id, String username) {
        PolicySet policySet = getOrThrow(id);

        if (policySet.getStatus() == PolicySetStatus.ARCHIVED) {
            return;
        }

        if (isReferencedByInFlightAnalysis(id)) {
            throw new ConflictException(
                "No se puede archivar: existen análisis en curso que dependen de este Policy Set");
        }

        policySet.setStatus(PolicySetStatus.ARCHIVED);
        policySet.setUpdatedAt(OffsetDateTime.now());
        policySetRepository.saveAndFlush(policySet);

        registrarAuditoria("POLICY_SET_ARCHIVED", username, id, Map.of("previousStatus", "ACTIVE"));
    }

    /** Symmetric with restoring an archived Policy: ARCHIVED -> ACTIVE, usable again immediately. */
    @Transactional
    public PolicySetResponse restore(UUID id, String username) {
        PolicySet policySet = getOrThrow(id);

        if (policySet.getStatus() != PolicySetStatus.ARCHIVED) {
            throw new BusinessValidationException("Solo se pueden restaurar Policy Sets en estado ARCHIVED");
        }

        policySet.setStatus(PolicySetStatus.ACTIVE);
        policySet.setUpdatedAt(OffsetDateTime.now());
        PolicySet saved = policySetRepository.saveAndFlush(policySet);

        registrarAuditoria("POLICY_SET_RESTORED", username, id, Map.of("previousStatus", "ARCHIVED"));

        return toResponse(saved);
    }

    private boolean isReferencedByInFlightAnalysis(UUID policySetId) {
        List<UUID> repositoryIds = policySelectionRepository.findRepositoryIdsByPolicySetId(policySetId);
        if (repositoryIds.isEmpty()) {
            return false;
        }
        return analysisRepository.existsByRepositoryIdInAndStatusIn(repositoryIds, IN_FLIGHT_STATUSES);
    }

    private List<Policy> resolveActivePolicies(List<UUID> policyIds) {
        List<Policy> found = policyRepository.findByIdIn(policyIds);
        Map<UUID, Policy> byId = found.stream().collect(Collectors.toMap(Policy::getId, p -> p));

        for (UUID id : policyIds) {
            Policy p = byId.get(id);
            if (p == null || p.getStatus() != PolicyStatus.ACTIVE) {
                throw new BusinessValidationException(
                    "La política '" + id + "' no existe o no está activa");
            }
        }
        return policyIds.stream().map(byId::get).collect(Collectors.toList());
    }

    private PolicySet getOrThrow(UUID id) {
        return policySetRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Policy Set no encontrado con id: " + id));
    }

    @Transactional(readOnly = true)
    public List<PolicyAuditLogEntryResponse> getAuditLog(UUID policySetId) {
        if (!policySetRepository.existsById(policySetId)) {
            throw new ResourceNotFoundException("Policy Set no encontrado con id: " + policySetId);
        }
        return jdbcTemplate.query(
            "SELECT id, action, user_id, username, \"timestamp\", payload " +
            "FROM policy_audit_log WHERE policy_set_id = ? ORDER BY \"timestamp\" DESC",
            (rs, rowNum) -> {
                UUID userId = (UUID) rs.getObject("user_id");
                Map<String, Object> payload;
                try {
                    String payloadJson = rs.getString("payload");
                    payload = payloadJson != null
                        ? objectMapper.readValue(payloadJson, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {})
                        : Map.of();
                } catch (JsonProcessingException e) {
                    payload = Map.of();
                }
                return new PolicyAuditLogEntryResponse(
                    (UUID) rs.getObject("id"),
                    rs.getString("action"),
                    userId,
                    rs.getString("username"),
                    rs.getObject("timestamp", OffsetDateTime.class),
                    payload
                );
            },
            policySetId
        );
    }

    private void registrarAuditoria(String action, String username, UUID policySetId, Map<String, Object> payload) {
        try {
            String payloadJson = objectMapper.writeValueAsString(payload);
            UUID userId = userRepository.findByUsername(username).map(User::getId).orElse(null);
            jdbcTemplate.update(
                "INSERT INTO policy_audit_log (action, policy_set_id, user_id, username, payload) " +
                "VALUES (?, ?, ?, ?, ?::jsonb)",
                action, policySetId, userId, username, payloadJson
            );
        } catch (JsonProcessingException | org.springframework.dao.DataAccessException e) {
            log.error("No se pudo registrar auditoría de policy set action={} policySet={}",
                action, policySetId, e);
        }
    }

    private PolicySetResponse toResponse(PolicySet ps) {
        List<Policy> policies = new ArrayList<>(ps.getPolicies());
        return new PolicySetResponse(
            ps.getId(),
            ps.getName(),
            ps.getDescription(),
            ps.getStatus(),
            ps.getVersion(),
            policies.stream().map(Policy::getId).collect(Collectors.toList()),
            policies.stream().map(Policy::getName).collect(Collectors.toList()),
            ps.getCreatedAt(),
            ps.getCreatedBy() != null ? ps.getCreatedBy().getId() : null,
            ps.getUpdatedAt()
        );
    }
}
