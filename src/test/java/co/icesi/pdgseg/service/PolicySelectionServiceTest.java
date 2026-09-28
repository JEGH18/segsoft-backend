package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.ApplyPolicySetRequest;
import co.icesi.pdgseg.dto.request.PolicySelectionRequest;
import co.icesi.pdgseg.dto.response.PolicySelectionResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicySelection;
import co.icesi.pdgseg.entity.PolicySet;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.enums.PolicySetStatus;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.entity.enums.RepositoryStatus;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.repository.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Covers "aplicar un Policy Set a un repositorio" (PDGSEGSOFT-276): wiring
 * policySetId through PolicySelectionRequest into PolicySelection, so a
 * Policy Set created in /policy-sets is actually usable from the analysis
 * flow, and so archiving that set can be blocked while a selection built
 * from it has an in-flight analysis (Gherkin escenario 5 of the sibling HU).
 */
@ExtendWith(MockitoExtension.class)
class PolicySelectionServiceTest {

    @Mock private PolicySelectionRepository policySelectionRepository;
    @Mock private RepositoryRepository repositoryRepository;
    @Mock private PolicyRepository policyRepository;
    @Mock private PolicySetRepository policySetRepository;
    @Mock private RuleRepository ruleRepository;
    @Mock private AnalysisRepository analysisRepository;
    @Mock private UserRepository userRepository;
    @Mock private JdbcTemplate jdbcTemplate;

    private PolicySelectionService service;

    @BeforeEach
    void setUp() {
        service = new PolicySelectionService(policySelectionRepository, repositoryRepository,
            policyRepository, policySetRepository, ruleRepository, analysisRepository,
            userRepository, jdbcTemplate, new ObjectMapper());
    }

    private Repository repo(UUID id) {
        return repo(id, RepositoryStatus.READY_FOR_ANALYSIS);
    }

    private Repository repo(UUID id, RepositoryStatus status) {
        Repository r = new Repository();
        ReflectionTestUtils.setField(r, "id", id);
        r.setStatus(status);
        return r;
    }

    private Policy activePolicyWithRule(UUID id) {
        Policy p = new Policy();
        p.setId(id);
        p.setName("Política " + id);
        p.setStatus(PolicyStatus.ACTIVE);
        return p;
    }

    private void stubHasRules(UUID policyId) {
        var projection = mock(PolicyRuleCountProjection.class);
        lenient().when(projection.getPolicyId()).thenReturn(policyId);
        lenient().when(projection.getRulesCount()).thenReturn(1L);
        lenient().when(ruleRepository.countEnabledRulesByPolicyIds(anyCollection())).thenReturn(List.of(projection));
    }

    @Test
    void createSelection_withPolicySetId_resolvesActiveSetAndStoresTraceability() {
        UUID repoId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();
        UUID policySetId = UUID.randomUUID();

        Policy policy = activePolicyWithRule(policyId);
        PolicySet policySet = new PolicySet();
        policySet.setId(policySetId);
        policySet.setName("Perfil PDG ICESI");
        policySet.setStatus(PolicySetStatus.ACTIVE);

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySelectionRepository.existsByRepositoryId(repoId)).thenReturn(false);
        when(policyRepository.findByIdIn(List.of(policyId))).thenReturn(List.of(policy));
        stubHasRules(policyId);
        when(policySetRepository.findById(policySetId)).thenReturn(Optional.of(policySet));
        when(policySelectionRepository.save(any(PolicySelection.class))).thenAnswer(inv -> { PolicySelection s = inv.getArgument(0); if (s.getId() == null) s.setId(UUID.randomUUID()); return s; });

        PolicySelectionRequest req = new PolicySelectionRequest(List.of(policyId), policySetId);
        PolicySelectionResponse resp = service.createSelection(repoId, req, "admin");

        assertThat(resp.policySetId()).isEqualTo(policySetId);
        assertThat(resp.policySetName()).isEqualTo("Perfil PDG ICESI");

        ArgumentCaptor<PolicySelection> captor = ArgumentCaptor.forClass(PolicySelection.class);
        verify(policySelectionRepository).save(captor.capture());
        assertThat(captor.getValue().getPolicySet()).isSameAs(policySet);
    }

    @Test
    void createSelection_policySetArchived_rejectsWithBusinessValidationException() {
        UUID repoId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();
        UUID policySetId = UUID.randomUUID();

        PolicySet archived = new PolicySet();
        archived.setId(policySetId);
        archived.setStatus(PolicySetStatus.ARCHIVED);

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySelectionRepository.existsByRepositoryId(repoId)).thenReturn(false);
        when(policyRepository.findByIdIn(List.of(policyId))).thenReturn(List.of(activePolicyWithRule(policyId)));
        stubHasRules(policyId);
        when(policySetRepository.findById(policySetId)).thenReturn(Optional.of(archived));

        PolicySelectionRequest req = new PolicySelectionRequest(List.of(policyId), policySetId);

        assertThatThrownBy(() -> service.createSelection(repoId, req, "admin"))
            .isInstanceOf(BusinessValidationException.class)
            .hasMessageContaining("no está activo");

        verify(policySelectionRepository, never()).save(any());
    }

    @Test
    void createSelection_policySetDoesNotExist_rejectsWithBusinessValidationException() {
        UUID repoId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();
        UUID missingSetId = UUID.randomUUID();

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySelectionRepository.existsByRepositoryId(repoId)).thenReturn(false);
        when(policyRepository.findByIdIn(List.of(policyId))).thenReturn(List.of(activePolicyWithRule(policyId)));
        stubHasRules(policyId);
        when(policySetRepository.findById(missingSetId)).thenReturn(Optional.empty());

        PolicySelectionRequest req = new PolicySelectionRequest(List.of(policyId), missingSetId);

        assertThatThrownBy(() -> service.createSelection(repoId, req, "admin"))
            .isInstanceOf(BusinessValidationException.class)
            .hasMessageContaining("no existe");
    }

    @Test
    void createSelection_withoutPolicySetId_hasNullTraceability() {
        UUID repoId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySelectionRepository.existsByRepositoryId(repoId)).thenReturn(false);
        when(policyRepository.findByIdIn(List.of(policyId))).thenReturn(List.of(activePolicyWithRule(policyId)));
        stubHasRules(policyId);
        when(policySelectionRepository.save(any(PolicySelection.class))).thenAnswer(inv -> { PolicySelection s = inv.getArgument(0); if (s.getId() == null) s.setId(UUID.randomUUID()); return s; });

        PolicySelectionRequest req = new PolicySelectionRequest(List.of(policyId), null);
        PolicySelectionResponse resp = service.createSelection(repoId, req, "admin");

        assertThat(resp.policySetId()).isNull();
        assertThat(resp.policySetName()).isNull();
        verify(policySetRepository, never()).findById(any());
    }

    @Test
    void updateSelection_manualEditWithoutPolicySetId_clearsPreviousLink() {
        UUID repoId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();
        UUID oldSetId = UUID.randomUUID();

        PolicySet oldSet = new PolicySet();
        oldSet.setId(oldSetId);
        oldSet.setStatus(PolicySetStatus.ACTIVE);

        PolicySelection existing = new PolicySelection();
        existing.setId(UUID.randomUUID());
        existing.setRepository(repo(repoId));
        existing.setPolicySet(oldSet);
        existing.setSelectedPolicyIds(List.of(policyId));

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySelectionRepository.findByRepositoryId(repoId)).thenReturn(Optional.of(existing));
        when(policyRepository.findByIdIn(List.of(policyId))).thenReturn(List.of(activePolicyWithRule(policyId)));
        stubHasRules(policyId);
        when(policySelectionRepository.save(any(PolicySelection.class))).thenAnswer(inv -> { PolicySelection s = inv.getArgument(0); if (s.getId() == null) s.setId(UUID.randomUUID()); return s; });

        // Manual edit: no policySetId sent -- the composition is no longer
        // guaranteed to match the set it came from, so the link must drop.
        PolicySelectionRequest req = new PolicySelectionRequest(List.of(policyId), null);
        PolicySelectionResponse resp = service.updateSelection(repoId, req, "admin");

        assertThat(resp.policySetId()).isNull();
        assertThat(existing.getPolicySet()).isNull();
    }

    // --- "Aplicar un Policy Set a un repositorio" (apply-set endpoint + source traceability) ---

    private PolicySet activeSet(UUID id, int version, Policy... policies) {
        PolicySet set = new PolicySet();
        set.setId(id);
        set.setName("Perfil PDG ICESI");
        set.setStatus(PolicySetStatus.ACTIVE);
        set.setVersion(version);
        set.setPolicies(new java.util.LinkedHashSet<>(List.of(policies)));
        return set;
    }

    @Test
    void applyPolicySet_activeSetAndReadyRepository_createsSelectionWithPolicySetSource() {
        UUID repoId = UUID.randomUUID();
        UUID policySetId = UUID.randomUUID();
        UUID p1 = UUID.randomUUID(), p2 = UUID.randomUUID(), p3 = UUID.randomUUID();

        PolicySet set = activeSet(policySetId, 2,
                activePolicyWithRule(p1), activePolicyWithRule(p2), activePolicyWithRule(p3));

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySetRepository.findById(policySetId)).thenReturn(Optional.of(set));
        when(policySelectionRepository.findByRepositoryId(repoId)).thenReturn(Optional.empty());
        when(policyRepository.findByIdIn(anyList())).thenReturn(List.of(
                activePolicyWithRule(p1), activePolicyWithRule(p2), activePolicyWithRule(p3)));
        lenient().when(ruleRepository.countEnabledRulesByPolicyIds(anyCollection()))
                .thenAnswer(inv -> {
                    List<UUID> ids = inv.getArgument(0);
                    return ids.stream().map(id -> {
                        var proj = mock(PolicyRuleCountProjection.class);
                        lenient().when(proj.getPolicyId()).thenReturn(id);
                        lenient().when(proj.getRulesCount()).thenReturn(1L);
                        return proj;
                    }).toList();
                });
        when(policySelectionRepository.save(any(PolicySelection.class))).thenAnswer(inv -> {
            PolicySelection s = inv.getArgument(0);
            if (s.getId() == null) s.setId(UUID.randomUUID());
            return s;
        });

        PolicySelectionResponse resp = service.applyPolicySet(
                repoId, new ApplyPolicySetRequest(policySetId), "admin");

        assertThat(resp.selectedPolicies()).hasSize(3);
        assertThat(resp.source()).isEqualTo("POLICY_SET:" + policySetId + ":2");
        assertThat(resp.policySetId()).isEqualTo(policySetId);

        ArgumentCaptor<PolicySelection> captor = ArgumentCaptor.forClass(PolicySelection.class);
        verify(policySelectionRepository).save(captor.capture());
        assertThat(captor.getValue().getSelectedPolicyIds()).containsExactlyInAnyOrder(p1, p2, p3);
        verify(jdbcTemplate).update(anyString(), any(), eq("POLICY_SET_APPLIED"), any(), eq("admin"), any());
    }

    @Test
    void updateSelection_afterApplyingPolicySet_manualAdjustment_marksSourceWithOrigin() {
        UUID repoId = UUID.randomUUID();
        UUID policySetId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();

        PolicySelection existing = new PolicySelection();
        existing.setId(UUID.randomUUID());
        existing.setRepository(repo(repoId));
        existing.setSelectedPolicyIds(List.of(policyId));
        existing.setSource("POLICY_SET:" + policySetId + ":2");

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySelectionRepository.findByRepositoryId(repoId)).thenReturn(Optional.of(existing));
        when(policyRepository.findByIdIn(List.of(policyId))).thenReturn(List.of(activePolicyWithRule(policyId)));
        stubHasRules(policyId);
        when(policySelectionRepository.save(any(PolicySelection.class))).thenAnswer(inv -> inv.getArgument(0));

        // Manual adjustment: policyIds change, no policySetId sent.
        PolicySelectionRequest req = new PolicySelectionRequest(List.of(policyId), null);
        PolicySelectionResponse resp = service.updateSelection(repoId, req, "admin");

        assertThat(resp.source()).isEqualTo(
                "MANUAL_ADJUSTMENT (from POLICY_SET:" + policySetId + ":2)");
        verify(jdbcTemplate).update(anyString(), any(), eq("POLICY_SELECTION_UPDATED"), any(), eq("admin"), any());
    }

    @Test
    void applyPolicySet_archivedSet_rejectsWithBusinessValidationException() {
        UUID repoId = UUID.randomUUID();
        UUID policySetId = UUID.randomUUID();

        PolicySet archived = new PolicySet();
        archived.setId(policySetId);
        archived.setName("ps-old");
        archived.setStatus(PolicySetStatus.ARCHIVED);

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(analysisRepository.existsByRepositoryIdAndStatusIn(eq(repoId), anyList())).thenReturn(false);
        when(policySetRepository.findById(policySetId)).thenReturn(Optional.of(archived));

        assertThatThrownBy(() -> service.applyPolicySet(
                repoId, new ApplyPolicySetRequest(policySetId), "admin"))
                .isInstanceOf(BusinessValidationException.class)
                .hasMessageContaining("está archivado y no puede aplicarse");

        verify(policySelectionRepository, never()).save(any());
    }

    @Test
    void applyPolicySet_repositoryNotReadyForAnalysis_rejectsWithConflictException() {
        UUID repoId = UUID.randomUUID();
        UUID policySetId = UUID.randomUUID();

        when(repositoryRepository.findById(repoId))
                .thenReturn(Optional.of(repo(repoId, RepositoryStatus.UPLOADING)));

        assertThatThrownBy(() -> service.applyPolicySet(
                repoId, new ApplyPolicySetRequest(policySetId), "admin"))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("no está listo para recibir una selección de políticas");

        verifyNoInteractions(policySetRepository);
        verify(policySelectionRepository, never()).save(any());
    }

    @Test
    void getSelection_appliedFromPolicySet_exposesSourceField() {
        UUID repoId = UUID.randomUUID();
        UUID policySetId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();

        PolicySelection existing = new PolicySelection();
        existing.setId(UUID.randomUUID());
        existing.setRepository(repo(repoId));
        existing.setSelectedPolicyIds(List.of(policyId));
        existing.setSource("POLICY_SET:" + policySetId + ":1");

        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repo(repoId)));
        when(policySelectionRepository.findByRepositoryId(repoId)).thenReturn(Optional.of(existing));
        when(policyRepository.findByIdIn(List.of(policyId))).thenReturn(List.of(activePolicyWithRule(policyId)));
        stubHasRules(policyId);

        PolicySelectionResponse resp = service.getSelection(repoId);

        assertThat(resp.source()).isEqualTo("POLICY_SET:" + policySetId + ":1");
    }
}
