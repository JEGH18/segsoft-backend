package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreatePolicyRequest;
import co.icesi.pdgseg.dto.request.UpdatePolicyRequest;
import co.icesi.pdgseg.dto.response.CategoryCoverageItem;
import co.icesi.pdgseg.dto.response.PolicyAuditLogEntryResponse;
import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.dto.response.PolicyTraceabilityResponse;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicyVersionHistory;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.entity.enums.RuleStatus;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.PolicyConflictException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.PolicySpecification;
import co.icesi.pdgseg.repository.PolicyVersionHistoryRepository;
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
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class PolicyService {

    private static final Logger log = LoggerFactory.getLogger(PolicyService.class);

    private static final List<AnalysisStatus> IN_FLIGHT_STATUSES = List.of(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING);

    private final PolicyRepository policyRepository;
    private final PolicyVersionHistoryRepository policyVersionHistoryRepository;
    private final AnalysisRepository analysisRepository;
    private final AnalysisSnapshotService analysisSnapshotService;
    private final UserRepository userRepository;
    private final RuleRepository ruleRepository;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final FrameworkControlService frameworkControlService;
    private final Iso27002ControlService iso27002ControlService;

    public PolicyService(PolicyRepository policyRepository,
                         PolicyVersionHistoryRepository policyVersionHistoryRepository,
                         AnalysisRepository analysisRepository,
                         AnalysisSnapshotService analysisSnapshotService,
                         UserRepository userRepository,
                         RuleRepository ruleRepository,
                         JdbcTemplate jdbcTemplate,
                         ObjectMapper objectMapper,
                         FrameworkControlService frameworkControlService,
                         Iso27002ControlService iso27002ControlService) {
        this.iso27002ControlService = iso27002ControlService;
        this.policyRepository = policyRepository;
        this.policyVersionHistoryRepository = policyVersionHistoryRepository;
        this.analysisRepository = analysisRepository;
        this.analysisSnapshotService = analysisSnapshotService;
        this.userRepository = userRepository;
        this.ruleRepository = ruleRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.frameworkControlService = frameworkControlService;
    }

    public Page<PolicyResponse> search(Framework framework, Category category,
                                        PolicyStatus status, String name, Pageable pageable) {
        // No status filter = every status (active, archived, deprecated) mixed
        // together, matching the "Todos los estados" option in the UI. Callers
        // that only want usable policies (e.g. building an analysis' policy
        // selection) must pass PolicyStatus.ACTIVE explicitly.
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

    /** Escenario 5: cadena de trazabilidad -- control Anexo A + guía 27002, cuando exista. */
    public PolicyTraceabilityResponse getTraceability(UUID id) {
        Policy p = policyRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Política no encontrada con id: " + id));

        String annexAControlName = frameworkControlService.findControl(p.getFramework(), p.getCategory())
            .map(fc -> fc.getControlName())
            .orElse(null);
        var annexAControl = new PolicyTraceabilityResponse.AnnexAControl(p.getControlId(), annexAControlName);

        PolicyTraceabilityResponse.ImplementationGuide implementationGuide = null;
        if (p.getImplementationGuideId() != null) {
            implementationGuide = iso27002ControlService.findById(p.getImplementationGuideId())
                .map(guide -> new PolicyTraceabilityResponse.ImplementationGuide(
                    guide.getId(), guide.getTitle(), guide.getImplementationGuidance()))
                .orElse(null);
        }

        return new PolicyTraceabilityResponse(
            p.getId(), p.getName(), p.getFramework().name(), annexAControl, implementationGuide);
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

        // CUSTOM = políticas definidas por el equipo, sin norma externa detrás:
        // no tiene catálogo, así que control_id se acepta como texto libre.
        // Cualquier otro framework SÍ tiene catálogo: el control_id nunca se toma del
        // request (evita que el usuario/API asigne el código de un control equivocado),
        // se deriva siempre del catálogo real de esa norma para esa categoría.
        String controlId = request.controlId();
        if (request.framework() != Framework.CUSTOM) {
            var control = frameworkControlService.findControl(request.framework(), request.category())
                .orElseThrow(() -> new BusinessValidationException(
                    "El marco normativo '" + request.framework() + "' no define un control para la categoría '"
                        + request.category() + "'"));
            controlId = control.getControlId();
        }

        // Escenario 1/3: implementationGuideId es opcional (omitirlo deja la
        // política detailPending=true), pero si se manda debe corresponder
        // realmente al controlId recién derivado -- nunca a texto libre.
        validateImplementationGuide(request.implementationGuideId(), request.framework(), controlId);

        Policy policy = new Policy();
        policy.setName(request.name());
        policy.setDescription(request.description());
        policy.setCategory(request.category());
        policy.setFramework(request.framework());
        policy.setControlId(controlId);
        policy.setImplementationGuideId(request.implementationGuideId());
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

    /**
     * Escenario 3: rechaza con 400 si el implementationGuideId no existe en
     * el catálogo 27002, o si existe pero corresponde a un control de
     * Anexo A distinto del controlId real de la política.
     */
    private void validateImplementationGuide(String implementationGuideId, Framework framework, String controlId) {
        if (implementationGuideId == null) {
            return;
        }
        if (framework != Framework.ISO_27001) {
            throw new BusinessValidationException(
                "implementationGuideId solo aplica a políticas del marco ISO_27001");
        }
        var guide = iso27002ControlService.findById(implementationGuideId)
            .orElseThrow(() -> new BusinessValidationException(
                "El control de ISO/IEC 27002 '" + implementationGuideId + "' no existe en el catálogo"));
        if (!guide.getCorrespondingAnnexAControl().equals(controlId)) {
            throw new BusinessValidationException(
                "El control de ISO/IEC 27002 seleccionado no corresponde al control del Anexo A indicado");
        }
    }

    /**
     * Only description, weight, and applicability may be updated. If an
     * If-Match version is supplied and it no longer matches the current
     * version, fails fast with 412 -- and even without it, JPA's @Version on
     * Policy.version still catches a genuine concurrent write at flush time,
     * so a losing racer gets the same 412 either way.
     */
    @Transactional
    public PolicyResponse patch(UUID id, UpdatePolicyRequest request, Integer ifMatchVersion, String username) {
        if (request.touchesImmutableFields()) {
            throw new BusinessValidationException(
                "Los campos 'framework', 'controlId' y 'category' no son editables. Cree una política nueva");
        }
        if (request.weight() != null && (request.weight() < 1 || request.weight() > 100)) {
            throw new BusinessValidationException("El peso debe ser un valor entre 1 y 100");
        }

        Policy policy = policyRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Política no encontrada con id: " + id));

        if (ifMatchVersion != null && !ifMatchVersion.equals(policy.getVersion())) {
            throw new ObjectOptimisticLockingFailureException(Policy.class, id);
        }

        Map<String, Object> diff = new LinkedHashMap<>();
        if (request.description() != null && !request.description().equals(policy.getDescription())) {
            diff.put("description", Map.of(
                "from", String.valueOf(policy.getDescription()),
                "to", request.description()));
        }
        if (request.weight() != null && !request.weight().equals(policy.getWeight())) {
            diff.put("weight", Map.of("from", policy.getWeight(), "to", request.weight()));
        }
        if (request.applicability() != null && !request.applicability().equals(policy.getApplicability())) {
            diff.put("applicability", Map.of(
                "from", policy.getApplicability(),
                "to", request.applicability()));
        }
        if (request.implementationGuideId() != null
                && !request.implementationGuideId().equals(policy.getImplementationGuideId())) {
            // Escenario 4's "completar el detalle": controlId/framework stay
            // immutable, but this is exactly how a detailPending policy gets
            // its ISO/IEC 27002 guide filled in after the fact.
            validateImplementationGuide(request.implementationGuideId(), policy.getFramework(), policy.getControlId());
            diff.put("implementationGuideId", Map.of(
                "from", String.valueOf(policy.getImplementationGuideId()),
                "to", request.implementationGuideId()));
        }

        if (diff.isEmpty()) {
            int count = ruleRepository.countByPolicyAndStatus(policy, RuleStatus.ACTIVE);
            return toResponse(policy, count, count > 0);
        }

        User editor = userRepository.findByUsername(username).orElseThrow(
            () -> new IllegalStateException("Usuario autenticado no encontrado: " + username));

        // Snapshot the state as it is RIGHT NOW (i.e. the version about to be
        // superseded) before mutating, so historical analyses stay traceable.
        policyVersionHistoryRepository.save(PolicyVersionHistory.snapshotOf(policy, editor));

        if (diff.containsKey("description")) policy.setDescription(request.description());
        if (diff.containsKey("weight")) policy.setWeight(request.weight());
        if (diff.containsKey("applicability")) policy.setApplicability(request.applicability());
        if (diff.containsKey("implementationGuideId")) policy.setImplementationGuideId(request.implementationGuideId());

        Policy saved = policyRepository.saveAndFlush(policy); // @Version increments here

        registrarAuditoria("POLICY_UPDATED", username, id, diff);

        int count = ruleRepository.countByPolicyAndStatus(saved, RuleStatus.ACTIVE);
        return toResponse(saved, count, count > 0);
    }

    /** Logical archive: never a physical DELETE, so past analyses keep full traceability. */
    @Transactional
    public void archive(UUID id, String username) {
        Policy policy = policyRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Política no encontrada con id: " + id));

        if (policy.getStatus() == PolicyStatus.ARCHIVED) {
            return;
        }

        if (isReferencedByInFlightAnalysis(id)) {
            throw new ConflictException("No se puede archivar: existen análisis en curso");
        }

        policy.setStatus(PolicyStatus.ARCHIVED);
        policyRepository.saveAndFlush(policy);

        registrarAuditoria("POLICY_ARCHIVED", username, id, Map.of("previousStatus", "ACTIVE"));
    }

    @Transactional
    public PolicyResponse restore(UUID id, String username) {
        Policy policy = policyRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Política no encontrada con id: " + id));

        if (policy.getStatus() != PolicyStatus.ARCHIVED) {
            throw new BusinessValidationException("Solo se pueden restaurar políticas en estado ARCHIVED");
        }

        policy.setStatus(PolicyStatus.ACTIVE);
        Policy saved = policyRepository.saveAndFlush(policy);

        registrarAuditoria("POLICY_RESTORED", username, id, Map.of("previousStatus", "ARCHIVED"));

        int count = ruleRepository.countByPolicyAndStatus(saved, RuleStatus.ACTIVE);
        return toResponse(saved, count, count > 0);
    }

    private boolean isReferencedByInFlightAnalysis(UUID policyId) {
        List<Analysis> inFlight = analysisRepository.findByStatusIn(IN_FLIGHT_STATUSES);
        for (Analysis analysis : inFlight) {
            try {
                boolean referenced = analysisSnapshotService.getSnapshot(analysis.getId()).policies().stream()
                    .anyMatch(p -> p.policyId().equals(policyId));
                if (referenced) {
                    return true;
                }
            } catch (IllegalStateException noSnapshotYet) {
                // Snapshot is written synchronously at QUEUED time, so this
                // shouldn't happen in practice -- skip rather than fail archiving.
            }
        }
        return false;
    }

    @Transactional(readOnly = true)
    public List<PolicyAuditLogEntryResponse> getAuditLog(UUID policyId) {
        if (!policyRepository.existsById(policyId)) {
            throw new ResourceNotFoundException("Política no encontrada con id: " + policyId);
        }
        return jdbcTemplate.query(
            "SELECT id, action, user_id, username, \"timestamp\", payload " +
            "FROM policy_audit_log WHERE policy_id = ? ORDER BY \"timestamp\" DESC",
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
            policyId
        );
    }

    private void registrarAuditoria(String action, String username, UUID policyId,
                                    Map<String, Object> payload) {
        try {
            String payloadJson = objectMapper.writeValueAsString(payload);
            UUID userId = userRepository.findByUsername(username).map(User::getId).orElse(null);
            jdbcTemplate.update(
                "INSERT INTO policy_audit_log (action, policy_id, user_id, username, payload) " +
                "VALUES (?, ?, ?, ?, ?::jsonb)",
                action, policyId, userId, username, payloadJson
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
        boolean detailPending = p.getFramework() == Framework.ISO_27001 && p.getImplementationGuideId() == null;
        return new PolicyResponse(
            p.getId(),
            p.getName(),
            p.getDescription(),
            p.getCategory(),
            p.getFramework(),
            p.getControlId(),
            p.getImplementationGuideId(),
            detailPending,
            p.getStatus(),
            p.getVersion(),
            p.getWeight(),
            p.getApplicability(),
            p.getCreatedAt(),
            createdById,
            executable,
            rulesCount
        );
    }
}
