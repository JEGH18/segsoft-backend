package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreatePolicySetRequest;
import co.icesi.pdgseg.dto.request.UpdatePolicySetRequest;
import co.icesi.pdgseg.dto.response.PolicySetResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicySet;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Verifies the 5 Gherkin scenarios of "Administrar el ciclo de vida de
 * Policy Sets": creación, rechazo por política inválida, edición no
 * retroactiva, archivado lógico, y bloqueo de archivado por análisis en
 * curso.
 */
@ExtendWith(MockitoExtension.class)
class PolicySetServiceTest {

    @Mock private PolicySetRepository policySetRepository;
    @Mock private PolicyRepository policyRepository;
    @Mock private PolicySelectionRepository policySelectionRepository;
    @Mock private AnalysisRepository analysisRepository;
    @Mock private UserRepository userRepository;
    @Mock private JdbcTemplate jdbcTemplate;

    private PolicySetService policySetService;

    @BeforeEach
    void setUp() {
        policySetService = new PolicySetService(policySetRepository, policyRepository,
            policySelectionRepository, analysisRepository, userRepository, jdbcTemplate, new ObjectMapper());
    }

    private Policy activePolicy(UUID id) {
        Policy p = new Policy();
        p.setId(id);
        p.setName("Política " + id);
        p.setStatus(PolicyStatus.ACTIVE);
        return p;
    }

    private User adminUser() {
        User u = new User();
        u.setId(UUID.randomUUID());
        u.setUsername("admin");
        return u;
    }

    private PolicySet buildActiveSet(UUID id, int version, Policy... policies) {
        PolicySet ps = new PolicySet();
        ps.setId(id);
        ps.setName("Perfil PDG ICESI");
        ps.setDescription("Conjunto base para validación de proyectos de grado");
        ps.setStatus(PolicySetStatus.ACTIVE);
        ps.setVersion(version);
        ps.setPolicies(new java.util.LinkedHashSet<>(List.of(policies)));
        ps.setCreatedAt(OffsetDateTime.now());
        ps.setUpdatedAt(OffsetDateTime.now());
        return ps;
    }

    // ── Escenario 1: creación ──────────────────────────────────────────

    @Test
    void create_withActivePolicies_persistsAndReturns201Shape() {
        UUID p1 = UUID.randomUUID(), p2 = UUID.randomUUID(), p3 = UUID.randomUUID();
        List<Policy> policies = List.of(activePolicy(p1), activePolicy(p2), activePolicy(p3));
        CreatePolicySetRequest req = new CreatePolicySetRequest(
            "Perfil PDG ICESI", "Conjunto base para validación de proyectos de grado", List.of(p1, p2, p3));

        when(policyRepository.findByIdIn(List.of(p1, p2, p3))).thenReturn(policies);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser()));
        when(policySetRepository.saveAndFlush(any(PolicySet.class))).thenAnswer(inv -> {
            PolicySet ps = inv.getArgument(0);
            ps.setId(UUID.randomUUID());
            ps.setCreatedAt(OffsetDateTime.now());
            return ps;
        });

        PolicySetResponse resp = policySetService.create(req, "admin");

        assertThat(resp.name()).isEqualTo("Perfil PDG ICESI");
        assertThat(resp.status()).isEqualTo(PolicySetStatus.ACTIVE);
        assertThat(resp.version()).isEqualTo(1);
        assertThat(resp.policyIds()).containsExactlyInAnyOrder(p1, p2, p3);
        verify(jdbcTemplate).update(contains("INSERT INTO policy_audit_log"),
            eq("POLICY_SET_CREATED"), any(UUID.class), any(UUID.class), eq("admin"), anyString());
    }

    // ── Escenario 2: rechazo por política inexistente o no activa ──────

    @Test
    void create_policyDoesNotExist_throwsBusinessValidationException400() {
        UUID missing = UUID.randomUUID();
        CreatePolicySetRequest req = new CreatePolicySetRequest("Set X", "desc", List.of(missing));

        when(policyRepository.findByIdIn(List.of(missing))).thenReturn(List.of());

        assertThatThrownBy(() -> policySetService.create(req, "admin"))
            .isInstanceOf(BusinessValidationException.class)
            .hasMessageContaining("'" + missing + "'")
            .hasMessageContaining("no existe o no está activa");

        verify(policySetRepository, never()).saveAndFlush(any());
    }

    @Test
    void create_policyIsArchived_throwsBusinessValidationException400() {
        UUID archivedId = UUID.randomUUID();
        Policy archived = activePolicy(archivedId);
        archived.setStatus(PolicyStatus.ARCHIVED);
        CreatePolicySetRequest req = new CreatePolicySetRequest("Set X", "desc", List.of(archivedId));

        when(policyRepository.findByIdIn(List.of(archivedId))).thenReturn(List.of(archived));

        assertThatThrownBy(() -> policySetService.create(req, "admin"))
            .isInstanceOf(BusinessValidationException.class)
            .hasMessageContaining("no existe o no está activa");

        verify(policySetRepository, never()).saveAndFlush(any());
    }

    // ── Escenario 3: edición no retroactiva ─────────────────────────────

    @Test
    void patch_addingAndRemovingPolicies_incrementsVersionByOneAndAudits() {
        UUID setId = UUID.randomUUID();
        UUID keep = UUID.randomUUID(), removeMe = UUID.randomUUID();
        UUID add1 = UUID.randomUUID(), add2 = UUID.randomUUID();
        PolicySet existing = buildActiveSet(setId, 3, activePolicy(keep), activePolicy(removeMe));

        when(policySetRepository.findById(setId)).thenReturn(Optional.of(existing));
        when(policyRepository.findByIdIn(List.of(keep, add1, add2)))
            .thenReturn(List.of(activePolicy(keep), activePolicy(add1), activePolicy(add2)));
        when(policySetRepository.saveAndFlush(any(PolicySet.class))).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser()));

        UpdatePolicySetRequest req = new UpdatePolicySetRequest(null, null, List.of(keep, add1, add2));

        PolicySetResponse resp = policySetService.patch(setId, req, "admin");

        assertThat(resp.version()).isEqualTo(4); // 3 -> 4, exactamente +1
        assertThat(resp.policyIds()).containsExactlyInAnyOrder(keep, add1, add2);
        assertThat(resp.policyIds()).doesNotContain(removeMe);

        verify(jdbcTemplate).update(contains("INSERT INTO policy_audit_log"),
            eq("POLICY_SET_UPDATED"), eq(setId), any(UUID.class), eq("admin"), anyString());
    }

    @Test
    void patch_noActualChanges_doesNotBumpVersion() {
        UUID setId = UUID.randomUUID();
        UUID p1 = UUID.randomUUID();
        PolicySet existing = buildActiveSet(setId, 2, activePolicy(p1));
        when(policySetRepository.findById(setId)).thenReturn(Optional.of(existing));

        UpdatePolicySetRequest req = new UpdatePolicySetRequest(null, null, null);

        PolicySetResponse resp = policySetService.patch(setId, req, "admin");

        assertThat(resp.version()).isEqualTo(2);
        verify(policySetRepository, never()).saveAndFlush(any());
        verify(jdbcTemplate, never()).update(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void patch_archivedPolicySet_rejectsEdit() {
        UUID setId = UUID.randomUUID();
        PolicySet archived = buildActiveSet(setId, 1);
        archived.setStatus(PolicySetStatus.ARCHIVED);
        when(policySetRepository.findById(setId)).thenReturn(Optional.of(archived));

        UpdatePolicySetRequest req = new UpdatePolicySetRequest("Nuevo nombre", null, null);

        assertThatThrownBy(() -> policySetService.patch(setId, req, "admin"))
            .isInstanceOf(BusinessValidationException.class);
    }

    // ── Escenario 4: archivado lógico preservando histórico ─────────────

    @Test
    void archive_movesActiveToArchived_neverDeletesPhysically() {
        UUID setId = UUID.randomUUID();
        PolicySet existing = buildActiveSet(setId, 1, activePolicy(UUID.randomUUID()));
        when(policySetRepository.findById(setId)).thenReturn(Optional.of(existing));
        when(policySelectionRepository.findRepositoryIdsByPolicySetId(setId)).thenReturn(List.of());
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser()));

        policySetService.archive(setId, "admin");

        assertThat(existing.getStatus()).isEqualTo(PolicySetStatus.ARCHIVED);
        verify(policySetRepository).saveAndFlush(existing);
        verify(policySetRepository, never()).delete(any());
        verify(policySetRepository, never()).deleteById(any());
        verify(jdbcTemplate).update(contains("INSERT INTO policy_audit_log"),
            eq("POLICY_SET_ARCHIVED"), eq(setId), any(UUID.class), eq("admin"), anyString());
    }

    @Test
    void archive_notFound_throwsResourceNotFoundException() {
        UUID setId = UUID.randomUUID();
        when(policySetRepository.findById(setId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> policySetService.archive(setId, "admin"))
            .isInstanceOf(ResourceNotFoundException.class);
    }

    // ── Escenario 5: bloqueo de archivado con análisis en curso ─────────

    @Test
    void archive_blockedByRunningAnalysisOnRepositoryUsingThisSet_throwsConflict409() {
        UUID setId = UUID.randomUUID();
        UUID repoId = UUID.randomUUID();
        PolicySet existing = buildActiveSet(setId, 1, activePolicy(UUID.randomUUID()));

        when(policySetRepository.findById(setId)).thenReturn(Optional.of(existing));
        when(policySelectionRepository.findRepositoryIdsByPolicySetId(setId)).thenReturn(List.of(repoId));
        when(analysisRepository.existsByRepositoryIdInAndStatusIn(
            List.of(repoId), List.of(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING)))
            .thenReturn(true);

        assertThatThrownBy(() -> policySetService.archive(setId, "admin"))
            .isInstanceOf(ConflictException.class)
            .hasMessageContaining("análisis en curso");

        assertThat(existing.getStatus()).isEqualTo(PolicySetStatus.ACTIVE); // no mutó
        verify(policySetRepository, never()).saveAndFlush(any());
    }

    @Test
    void archive_notReferencedByAnyRunningAnalysis_succeeds() {
        UUID setId = UUID.randomUUID();
        UUID repoId = UUID.randomUUID();
        PolicySet existing = buildActiveSet(setId, 1, activePolicy(UUID.randomUUID()));

        when(policySetRepository.findById(setId)).thenReturn(Optional.of(existing));
        when(policySelectionRepository.findRepositoryIdsByPolicySetId(setId)).thenReturn(List.of(repoId));
        when(analysisRepository.existsByRepositoryIdInAndStatusIn(
            List.of(repoId), List.of(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING)))
            .thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser()));

        policySetService.archive(setId, "admin");

        assertThat(existing.getStatus()).isEqualTo(PolicySetStatus.ARCHIVED);
    }

    // ── Restaurar: ARCHIVED -> ACTIVE, disponible de nuevo de inmediato ──

    @Test
    void restore_movesArchivedBackToActive_andAudits() {
        UUID setId = UUID.randomUUID();
        PolicySet archived = buildActiveSet(setId, 2, activePolicy(UUID.randomUUID()));
        archived.setStatus(PolicySetStatus.ARCHIVED);

        when(policySetRepository.findById(setId)).thenReturn(Optional.of(archived));
        when(policySetRepository.saveAndFlush(any(PolicySet.class))).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser()));

        PolicySetResponse resp = policySetService.restore(setId, "admin");

        assertThat(resp.status()).isEqualTo(PolicySetStatus.ACTIVE);
        verify(jdbcTemplate).update(contains("INSERT INTO policy_audit_log"),
            eq("POLICY_SET_RESTORED"), eq(setId), any(UUID.class), eq("admin"), anyString());
    }

    @Test
    void restore_rejectsNonArchivedPolicySet() {
        UUID setId = UUID.randomUUID();
        PolicySet active = buildActiveSet(setId, 1, activePolicy(UUID.randomUUID())); // still ACTIVE
        when(policySetRepository.findById(setId)).thenReturn(Optional.of(active));

        assertThatThrownBy(() -> policySetService.restore(setId, "admin"))
            .isInstanceOf(BusinessValidationException.class);

        verify(policySetRepository, never()).saveAndFlush(any());
    }
}
