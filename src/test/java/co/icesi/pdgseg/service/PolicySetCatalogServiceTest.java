package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.PolicySetDetailResponse;
import co.icesi.pdgseg.dto.response.PolicySetPageResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.PolicySet;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicySetStatus;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Covers "Listar y consultar el catálogo de Policy Sets": the 5 Gherkin
 * scenarios (listado paginado, detalle, filtrado por estado, catálogo
 * vacío, búsqueda por nombre).
 */
@ExtendWith(MockitoExtension.class)
class PolicySetCatalogServiceTest {

    @Mock private PolicySetRepository policySetRepository;
    @Mock private PolicyRepository policyRepository;
    @Mock private PolicySelectionRepository policySelectionRepository;
    @Mock private AnalysisRepository analysisRepository;
    @Mock private UserRepository userRepository;
    @Mock private JdbcTemplate jdbcTemplate;

    private PolicySetService service;

    @BeforeEach
    void setUp() {
        service = new PolicySetService(policySetRepository, policyRepository,
            policySelectionRepository, analysisRepository, userRepository, jdbcTemplate, new ObjectMapper());
    }

    private Policy policy(String name, Framework framework, Category category) {
        Policy p = new Policy();
        p.setId(UUID.randomUUID());
        p.setName(name);
        p.setStatus(PolicyStatus.ACTIVE);
        p.setFramework(framework);
        p.setCategory(category);
        return p;
    }

    private PolicySet policySet(String name, PolicySetStatus status, Policy... policies) {
        PolicySet ps = new PolicySet();
        ps.setId(UUID.randomUUID());
        ps.setName(name);
        ps.setDescription("desc");
        ps.setStatus(status);
        ps.setVersion(1);
        ps.setPolicies(new LinkedHashSet<>(List.of(policies)));
        ps.setCreatedAt(OffsetDateTime.now());
        ps.setUpdatedAt(OffsetDateTime.now());
        return ps;
    }

    // ── Escenario 1: listado paginado, default ACTIVE ──────────────────

    @Test
    void list_noStatusGiven_defaultsToActiveAndReturnsPaginationMetadata() {
        PolicySet a = policySet("Perfil A", PolicySetStatus.ACTIVE);
        // Page size 1 so PageImpl's own "offset + pageSize > total => this
        // must be the last page" correction doesn't kick in and silently
        // override the total we're asserting on below.
        Pageable pageable = PageRequest.of(0, 1);
        PageImpl<PolicySet> page = new PageImpl<>(List.of(a), pageable, 9);

        when(policySetRepository.findByStatusAndNameContainingIgnoreCase(
                eq(PolicySetStatus.ACTIVE), eq(""), eq(pageable)))
            .thenReturn(page);
        when(policySetRepository.count()).thenReturn(12L);

        PolicySetPageResponse resp = service.list(null, null, pageable);

        assertThat(resp.page()).isEqualTo(0);
        assertThat(resp.size()).isEqualTo(1);
        assertThat(resp.totalElements()).isEqualTo(9);
        assertThat(resp.content()).hasSize(1);
        assertThat(resp.message()).isNull(); // catalog isn't empty, just this call returned few
    }

    // ── Escenario 2: detalle -- políticas, categoryCoverage, usageCount ─

    @Test
    void findDetailById_returnsFullPolicies_categoryCoverageAcrossAll5Categories_andUsageCount() {
        Policy sqlPolicy = policy("Prevención de SQL Injection", Framework.OWASP_TOP_10_2021, Category.SQL_INJECTION);
        Policy xssPolicy = policy("Sanitización de HTML", Framework.OWASP_ASVS, Category.XSS);
        Policy anotherSqlPolicy = policy("Control de acceso a datos", Framework.ISO_27001, Category.SQL_INJECTION);
        PolicySet ps = policySet("ps-pdg-icesi", PolicySetStatus.ACTIVE, sqlPolicy, xssPolicy, anotherSqlPolicy);

        when(policySetRepository.findById(ps.getId())).thenReturn(Optional.of(ps));
        when(policySelectionRepository.findRepositoryIdsByPolicySetId(ps.getId()))
            .thenReturn(List.of(UUID.randomUUID(), UUID.randomUUID())); // applied to 2 repos

        PolicySetDetailResponse resp = service.findDetailById(ps.getId());

        assertThat(resp.policies()).hasSize(3);
        assertThat(resp.policies()).extracting("name")
            .containsExactlyInAnyOrder("Prevención de SQL Injection", "Sanitización de HTML", "Control de acceso a datos");
        assertThat(resp.policies()).allSatisfy(summary -> {
            assertThat(summary.id()).isNotNull();
            assertThat(summary.framework()).isNotNull();
            assertThat(summary.category()).isNotNull();
        });

        // All 5 categories present, even the ones with zero policies.
        assertThat(resp.categoryCoverage()).hasSize(Category.values().length);
        assertThat(resp.categoryCoverage().get(Category.SQL_INJECTION)).isEqualTo(2L);
        assertThat(resp.categoryCoverage().get(Category.XSS)).isEqualTo(1L);
        assertThat(resp.categoryCoverage().get(Category.AUTHENTICATION_FAILURE)).isEqualTo(0L);
        assertThat(resp.categoryCoverage().get(Category.INSECURE_DATA_HANDLING)).isEqualTo(0L);
        assertThat(resp.categoryCoverage().get(Category.DEPENDENCY_VULNERABILITY)).isEqualTo(0L);

        assertThat(resp.usageCount()).isEqualTo(2);
        assertThat(resp.version()).isEqualTo(1);
    }

    @Test
    void findDetailById_notFound_throwsResourceNotFoundException() {
        UUID id = UUID.randomUUID();
        when(policySetRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.findDetailById(id))
            .isInstanceOf(ResourceNotFoundException.class);
    }

    // ── Escenario 3: filtrado por estado ────────────────────────────────

    @Test
    void list_statusArchived_queriesRepositoryWithArchived() {
        Pageable pageable = PageRequest.of(0, 10);
        when(policySetRepository.findByStatusAndNameContainingIgnoreCase(
                eq(PolicySetStatus.ARCHIVED), eq(""), eq(pageable)))
            .thenReturn(new PageImpl<>(List.of(), pageable, 3));
        when(policySetRepository.count()).thenReturn(12L);

        PolicySetPageResponse resp = service.list(PolicySetStatus.ARCHIVED, null, pageable);

        assertThat(resp.totalElements()).isEqualTo(3);
        verify(policySetRepository).findByStatusAndNameContainingIgnoreCase(
            eq(PolicySetStatus.ARCHIVED), eq(""), eq(pageable));
    }

    // ── Escenario 4: catálogo vacío ──────────────────────────────────────

    @Test
    void list_noPolicySetsExistAtAll_includesCreateOneMessage() {
        Pageable pageable = PageRequest.of(0, 10);
        when(policySetRepository.findByStatusAndNameContainingIgnoreCase(
                eq(PolicySetStatus.ACTIVE), eq(""), eq(pageable)))
            .thenReturn(new PageImpl<>(List.of(), pageable, 0));
        when(policySetRepository.count()).thenReturn(0L);

        PolicySetPageResponse resp = service.list(null, null, pageable);

        assertThat(resp.content()).isEmpty();
        assertThat(resp.message()).isEqualTo("No hay Policy Sets registrados. Cree uno para estandarizar sus análisis.");
    }

    @Test
    void list_catalogNotEmpty_butThisFilterMatchesNothing_doesNotShowCreateOneMessage() {
        // A search/status combo that legitimately matches zero rows is NOT
        // the same thing as "the whole catalog is empty" -- only the latter
        // gets the call-to-action message.
        Pageable pageable = PageRequest.of(0, 10);
        when(policySetRepository.findByStatusAndNameContainingIgnoreCase(
                eq(PolicySetStatus.ACTIVE), eq("nonexistent"), eq(pageable)))
            .thenReturn(new PageImpl<>(List.of(), pageable, 0));
        when(policySetRepository.count()).thenReturn(12L);

        PolicySetPageResponse resp = service.list(null, "nonexistent", pageable);

        assertThat(resp.content()).isEmpty();
        assertThat(resp.message()).isNull();
    }

    // ── Escenario 5: búsqueda por nombre ─────────────────────────────────

    @Test
    void list_withSearch_passesItThroughCaseInsensitively() {
        PolicySet match = policySet("Perfil PDG ICESI", PolicySetStatus.ACTIVE);
        Pageable pageable = PageRequest.of(0, 10);
        when(policySetRepository.findByStatusAndNameContainingIgnoreCase(
                eq(PolicySetStatus.ACTIVE), eq("ICESI"), eq(pageable)))
            .thenReturn(new PageImpl<>(List.of(match), pageable, 1));
        when(policySetRepository.count()).thenReturn(12L);

        PolicySetPageResponse resp = service.list(null, "ICESI", pageable);

        assertThat(resp.content()).hasSize(1);
        assertThat(resp.content().get(0).name()).isEqualTo("Perfil PDG ICESI");
    }

    @Test
    void list_nullSearch_defaultsToEmptyStringSoItMatchesEveryName() {
        Pageable pageable = PageRequest.of(0, 10);
        ArgumentCaptor<String> searchCaptor = ArgumentCaptor.forClass(String.class);
        when(policySetRepository.findByStatusAndNameContainingIgnoreCase(
                eq(PolicySetStatus.ACTIVE), searchCaptor.capture(), eq(pageable)))
            .thenReturn(new PageImpl<>(List.of(), pageable, 0));
        when(policySetRepository.count()).thenReturn(0L);

        service.list(null, null, pageable);

        assertThat(searchCaptor.getValue()).isEqualTo("");
    }
}
