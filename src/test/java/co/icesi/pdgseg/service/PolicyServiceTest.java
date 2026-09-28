package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreatePolicyRequest;
import co.icesi.pdgseg.dto.request.UpdatePolicyRequest;
import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.FrameworkControl;
import co.icesi.pdgseg.entity.Iso27002Control;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.dto.snapshot.AnalysisSnapshotDto;
import co.icesi.pdgseg.dto.snapshot.PolicySnapshotDto;
import co.icesi.pdgseg.exception.BusinessValidationException;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.PolicyConflictException;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.PolicyVersionHistoryRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyServiceTest {

    @Mock private PolicyRepository policyRepository;
    @Mock private PolicyVersionHistoryRepository policyVersionHistoryRepository;
    @Mock private AnalysisRepository analysisRepository;
    @Mock private AnalysisSnapshotService analysisSnapshotService;
    @Mock private UserRepository userRepository;
    @Mock private RuleRepository ruleRepository;
    @Mock private JdbcTemplate jdbcTemplate;
    @Mock private FrameworkControlService frameworkControlService;
    @Mock private Iso27002ControlService iso27002ControlService;

    private PolicyService policyService;

    @BeforeEach
    void setUp() {
        policyService = new PolicyService(policyRepository, policyVersionHistoryRepository,
                analysisRepository, analysisSnapshotService, userRepository,
                ruleRepository, jdbcTemplate, new ObjectMapper(), frameworkControlService, iso27002ControlService);

        // Default: any (framework, category) resolves to some catalog control, so
        // existing create() tests that don't care about the catalog don't need to
        // stub it themselves. Tests that DO care (catalog hit/miss) override this.
        FrameworkControl anyControl = mock(FrameworkControl.class);
        lenient().when(anyControl.getControlId()).thenReturn("A03:2021");
        lenient().when(frameworkControlService.findControl(any(), any())).thenReturn(Optional.of(anyControl));
    }

    private Policy buildActivePolicy(UUID id, int version, int weight) {
        Policy p = new Policy();
        p.setId(id);
        p.setName("Política de prueba");
        p.setDescription("Descripción original con la longitud mínima requerida.");
        p.setCategory(Category.SQL_INJECTION);
        p.setFramework(Framework.OWASP_TOP_10_2021);
        p.setControlId("A03:2021");
        p.setStatus(PolicyStatus.ACTIVE);
        p.setVersion(version);
        p.setWeight(weight);
        p.setCreatedAt(OffsetDateTime.now());
        return p;
    }

    private User buildUser(String username) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername(username);
        return user;
    }

    private Policy buildSavedPolicy(CreatePolicyRequest req, User creator) {
        Policy p = new Policy();
        p.setId(UUID.randomUUID());
        p.setName(req.name());
        p.setDescription(req.description());
        p.setCategory(req.category());
        p.setFramework(req.framework());
        p.setControlId(req.controlId());
        p.setStatus(PolicyStatus.ACTIVE);
        p.setVersion(1);
        p.setWeight(50);
        p.setCreatedAt(OffsetDateTime.now());
        p.setCreatedBy(creator);
        return p;
    }

    @Test
    void create_success_returnsCreatedPolicy() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política SQL básica",
            "Previene inyecciones SQL mediante uso de queries parametrizadas en todas las capas de acceso a datos.",
            Category.SQL_INJECTION,
            Framework.OWASP_TOP_10_2021,
            "A03:2021"
        );
        User user = buildUser("admin");
        Policy saved = buildSavedPolicy(req, user);

        when(policyRepository.existsByNameAndFramework(req.name(), req.framework())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenReturn(saved);

        PolicyResponse response = policyService.create(req, "admin");

        assertThat(response.name()).isEqualTo("Política SQL básica");
        assertThat(response.status()).isEqualTo(PolicyStatus.ACTIVE);
        assertThat(response.version()).isEqualTo(1);
        assertThat(response.weight()).isEqualTo(50);
        assertThat(response.category()).isEqualTo(Category.SQL_INJECTION);
        assertThat(response.framework()).isEqualTo(Framework.OWASP_TOP_10_2021);
        assertThat(response.createdById()).isEqualTo(user.getId());
    }

    @Test
    void create_duplicate_throwsConflict() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política duplicada",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.XSS,
            Framework.ISO_27001,
            null
        );

        when(policyRepository.existsByNameAndFramework("Política duplicada", Framework.ISO_27001))
            .thenReturn(true);

        assertThatThrownBy(() -> policyService.create(req, "admin"))
            .isInstanceOf(PolicyConflictException.class)
            .hasMessageContaining("Política duplicada");

        verify(policyRepository, never()).saveAndFlush(any());
    }

    @Test
    void create_auditsEventOnSuccess() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Auditoría SQL XSS",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.XSS,
            Framework.OWASP_ASVS,
            null
        );
        User user = buildUser("admin");
        Policy saved = buildSavedPolicy(req, user);

        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(policyRepository.saveAndFlush(any())).thenReturn(saved);

        policyService.create(req, "admin");

        verify(jdbcTemplate).update(
            contains("INSERT INTO policy_audit_log"),
            eq("POLICY_CREATED"), any(UUID.class), any(UUID.class), eq("admin"), anyString()
        );
    }

    @Test
    void create_setsStatusActiveAndVersionOne() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Policy v1 activa",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.AUTHENTICATION_FAILURE,
            Framework.OWASP_TOP_10_2021,
            "A07:2021"
        );
        User user = buildUser("admin");

        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> {
            Policy p = inv.getArgument(0);
            p.setId(UUID.randomUUID());
            p.setCreatedAt(OffsetDateTime.now());
            return p;
        });

        PolicyResponse resp = policyService.create(req, "admin");

        assertThat(resp.status()).isEqualTo(PolicyStatus.ACTIVE);
        assertThat(resp.version()).isEqualTo(1);

        ArgumentCaptor<Policy> captor = ArgumentCaptor.forClass(Policy.class);
        verify(policyRepository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo(PolicyStatus.ACTIVE);
        assertThat(captor.getValue().getVersion()).isEqualTo(1);
    }

    @Test
    void create_allFiveCategories_succeed() {
        User user = buildUser("admin");
        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> {
            Policy p = inv.getArgument(0);
            p.setId(UUID.randomUUID());
            p.setCreatedAt(OffsetDateTime.now());
            return p;
        });

        for (Category cat : Category.values()) {
            CreatePolicyRequest req = new CreatePolicyRequest(
                "Política " + cat.name(),
                "Descripción con la longitud mínima requerida de veinte caracteres.",
                cat,
                Framework.OWASP_TOP_10_2021,
                null
            );
            PolicyResponse resp = policyService.create(req, "admin");
            assertThat(resp.category()).isEqualTo(cat);
        }
    }

    // ── Catálogo de controles: control_id se deriva, no se acepta libre ────

    @Test
    void create_derivesControlIdFromCatalog_ignoringClientSuppliedValue() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política con control incorrecto",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.SQL_INJECTION,
            Framework.ISO_27001,
            "A.10.1.1" // control real, pero de otra categoría (cifrado, no control de acceso)
        );
        User user = buildUser("admin");
        FrameworkControl realControl = mock(FrameworkControl.class);
        when(realControl.getControlId()).thenReturn("A.9.4.1");
        when(frameworkControlService.findControl(Framework.ISO_27001, Category.SQL_INJECTION))
            .thenReturn(Optional.of(realControl));

        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> inv.getArgument(0));

        PolicyResponse resp = policyService.create(req, "admin");

        assertThat(resp.controlId()).isEqualTo("A.9.4.1");

        ArgumentCaptor<Policy> captor = ArgumentCaptor.forClass(Policy.class);
        verify(policyRepository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getControlId()).isEqualTo("A.9.4.1");
    }

    // ── "Incorporar políticas basadas en NIST al catálogo": Escenario 1 ────

    @Test
    void create_nistFramework_isAcceptedAndDerivesTheCatalogControl_matchingGherkinExample() {
        // Mirrors the Gherkin literally: framework NIST_SP_800_53, category
        // whose catalog control is SC-13 "Cryptographic Protection".
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Cifrado de datos en reposo (NIST)",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.INSECURE_DATA_HANDLING,
            Framework.NIST_SP_800_53,
            "algo-que-el-cliente-mande-y-debe-ser-ignorado"
        );
        User user = buildUser("admin");
        FrameworkControl sc13 = mock(FrameworkControl.class);
        when(sc13.getControlId()).thenReturn("SC-13");
        when(frameworkControlService.findControl(Framework.NIST_SP_800_53, Category.INSECURE_DATA_HANDLING))
            .thenReturn(Optional.of(sc13));

        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> {
            Policy p = inv.getArgument(0);
            p.setId(UUID.randomUUID());
            p.setCreatedAt(OffsetDateTime.now());
            return p;
        });

        PolicyResponse resp = policyService.create(req, "admin");

        assertThat(resp.framework()).isEqualTo(Framework.NIST_SP_800_53);
        assertThat(resp.controlId()).isEqualTo("SC-13"); // derivado, no el que mandó el cliente
    }

    // ── "Derivar políticas del catálogo a partir de ISO/IEC 27002" ─────────

    private Iso27002Control iso27002Control(String id, String title, String correspondingAnnexA) {
        Iso27002Control c = new Iso27002Control();
        ReflectionTestUtils.setField(c, "id", id);
        ReflectionTestUtils.setField(c, "title", title);
        ReflectionTestUtils.setField(c, "implementationGuidance", "Guía de implementación de prueba.");
        ReflectionTestUtils.setField(c, "correspondingAnnexAControl", correspondingAnnexA);
        return c;
    }

    @Test
    void create_iso27001WithMatchingImplementationGuideId_persistsBothReferences_matchesGherkinExample() {
        // Escenario 1: framework ISO_IEC_27001, control Anexo A "A.8.24",
        // guía 27002 "8.24 - Use of cryptography".
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Cifrado de datos en reposo (27002)",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.INSECURE_DATA_HANDLING,
            Framework.ISO_27001,
            null,
            "8.24"
        );
        FrameworkControl annexA = mock(FrameworkControl.class);
        when(annexA.getControlId()).thenReturn("A.8.24");
        when(frameworkControlService.findControl(Framework.ISO_27001, Category.INSECURE_DATA_HANDLING))
            .thenReturn(Optional.of(annexA));
        when(iso27002ControlService.findById("8.24"))
            .thenReturn(Optional.of(iso27002Control("8.24", "Use of cryptography", "A.8.24")));

        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(buildUser("admin")));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> {
            Policy p = inv.getArgument(0);
            p.setId(UUID.randomUUID());
            p.setCreatedAt(OffsetDateTime.now());
            return p;
        });

        PolicyResponse resp = policyService.create(req, "admin");

        assertThat(resp.controlId()).isEqualTo("A.8.24");
        assertThat(resp.implementationGuideId()).isEqualTo("8.24");
        assertThat(resp.detailPending()).isFalse();
    }

    @Test
    void create_iso27001WithoutImplementationGuideId_leavesItNull_andDetailPendingTrue() {
        // Escenario 4 (mitad "alta"): omitir la guía es válido -- la política
        // queda pendiente de detalle, no rechazada.
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Cifrado de datos en reposo, sin detalle aún",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.INSECURE_DATA_HANDLING,
            Framework.ISO_27001,
            null,
            null
        );
        FrameworkControl annexA = mock(FrameworkControl.class);
        when(annexA.getControlId()).thenReturn("A.8.24");
        when(frameworkControlService.findControl(Framework.ISO_27001, Category.INSECURE_DATA_HANDLING))
            .thenReturn(Optional.of(annexA));

        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(buildUser("admin")));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> {
            Policy p = inv.getArgument(0);
            p.setId(UUID.randomUUID());
            p.setCreatedAt(OffsetDateTime.now());
            return p;
        });

        PolicyResponse resp = policyService.create(req, "admin");

        assertThat(resp.implementationGuideId()).isNull();
        assertThat(resp.detailPending()).isTrue();
        verifyNoInteractions(iso27002ControlService);
    }

    @Test
    void create_implementationGuideDoesNotCorrespondToControlId_rejectsWith400AndExactMessage() {
        // Escenario 3.
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política con guía incorrecta",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.INSECURE_DATA_HANDLING,
            Framework.ISO_27001,
            null,
            "8.5" // "Secure authentication" -- no corresponde a INSECURE_DATA_HANDLING (A.8.24)
        );
        FrameworkControl annexA = mock(FrameworkControl.class);
        when(annexA.getControlId()).thenReturn("A.8.24");
        when(frameworkControlService.findControl(Framework.ISO_27001, Category.INSECURE_DATA_HANDLING))
            .thenReturn(Optional.of(annexA));
        when(iso27002ControlService.findById("8.5"))
            .thenReturn(Optional.of(iso27002Control("8.5", "Secure authentication", "A.8.5")));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(buildUser("admin")));

        assertThatThrownBy(() -> policyService.create(req, "admin"))
            .isInstanceOf(BusinessValidationException.class)
            .hasMessage("El control de ISO/IEC 27002 seleccionado no corresponde al control del Anexo A indicado");

        verify(policyRepository, never()).saveAndFlush(any());
    }

    @Test
    void create_implementationGuideIdDoesNotExistInCatalog_rejects400() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política con guía inexistente",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.INSECURE_DATA_HANDLING,
            Framework.ISO_27001,
            null,
            "99.99"
        );
        FrameworkControl annexA = mock(FrameworkControl.class);
        when(annexA.getControlId()).thenReturn("A.8.24");
        when(frameworkControlService.findControl(Framework.ISO_27001, Category.INSECURE_DATA_HANDLING))
            .thenReturn(Optional.of(annexA));
        when(iso27002ControlService.findById("99.99")).thenReturn(Optional.empty());
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(buildUser("admin")));

        assertThatThrownBy(() -> policyService.create(req, "admin"))
            .isInstanceOf(BusinessValidationException.class);

        verify(policyRepository, never()).saveAndFlush(any());
    }

    @Test
    void create_implementationGuideId_onNonIso27001Framework_isRejected() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política OWASP con guía 27002 (inválido)",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.SQL_INJECTION,
            Framework.OWASP_TOP_10_2021,
            null,
            "8.28"
        );
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(buildUser("admin")));

        assertThatThrownBy(() -> policyService.create(req, "admin"))
            .isInstanceOf(BusinessValidationException.class)
            .hasMessageContaining("solo aplica a políticas del marco ISO_27001");

        verify(policyRepository, never()).saveAndFlush(any());
        verifyNoInteractions(iso27002ControlService);
    }

    @Test
    void patch_completingImplementationGuideId_onDetailPendingPolicy_succeedsAndAudits() {
        // Escenario 4 (mitad "completar detalle"): la invitación de la UI
        // lleva a un PATCH que rellena implementationGuideId sin tocar
        // controlId/framework/category, que siguen inmutables.
        UUID id = UUID.randomUUID();
        Policy existing = buildActivePolicy(id, 1, 50);
        existing.setFramework(Framework.ISO_27001);
        existing.setControlId("A.8.24");
        existing.setImplementationGuideId(null);

        when(policyRepository.findById(id)).thenReturn(Optional.of(existing));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(buildUser("admin")));
        when(iso27002ControlService.findById("8.24"))
            .thenReturn(Optional.of(iso27002Control("8.24", "Use of cryptography", "A.8.24")));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> inv.getArgument(0));

        UpdatePolicyRequest req = new UpdatePolicyRequest(null, null, null, null, null, null, "8.24");
        PolicyResponse resp = policyService.patch(id, req, null, "admin");

        assertThat(resp.implementationGuideId()).isEqualTo("8.24");
        assertThat(resp.detailPending()).isFalse();
        verify(jdbcTemplate).update(anyString(), eq("POLICY_UPDATED"), eq(id), any(), eq("admin"), anyString());
    }

    @Test
    void findById_iso27001PolicyWithoutGuide_isMarkedDetailPending() {
        // Escenario 4 (mitad "listado"): sin implementationGuideId, ISO_27001 -> detailPending=true.
        UUID id = UUID.randomUUID();
        Policy legacy = buildActivePolicy(id, 1, 50);
        legacy.setFramework(Framework.ISO_27001);
        legacy.setControlId("A.8.24");
        legacy.setImplementationGuideId(null);
        when(policyRepository.findById(id)).thenReturn(Optional.of(legacy));

        PolicyResponse resp = policyService.findById(id);

        assertThat(resp.detailPending()).isTrue();
    }

    @Test
    void findById_nonIso27001Policy_isNeverDetailPending_regardlessOfMissingGuide() {
        UUID id = UUID.randomUUID();
        Policy owaspPolicy = buildActivePolicy(id, 1, 50); // framework=OWASP_TOP_10_2021 by default
        when(policyRepository.findById(id)).thenReturn(Optional.of(owaspPolicy));

        PolicyResponse resp = policyService.findById(id);

        assertThat(resp.detailPending()).isFalse();
    }

    @Test
    void getTraceability_policyWithBothReferences_includesAnnexAControlAndImplementationGuide() {
        // Escenario 5.
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 1, 50);
        policy.setFramework(Framework.ISO_27001);
        policy.setCategory(Category.INSECURE_DATA_HANDLING);
        policy.setControlId("A.8.24");
        policy.setImplementationGuideId("8.24");

        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));
        FrameworkControl annexA = mock(FrameworkControl.class);
        when(annexA.getControlName()).thenReturn("Uso de criptografía");
        when(frameworkControlService.findControl(Framework.ISO_27001, Category.INSECURE_DATA_HANDLING))
            .thenReturn(Optional.of(annexA));
        when(iso27002ControlService.findById("8.24"))
            .thenReturn(Optional.of(iso27002Control("8.24", "Use of cryptography", "A.8.24")));

        var trace = policyService.getTraceability(id);

        assertThat(trace.annexAControl().id()).isEqualTo("A.8.24");
        assertThat(trace.annexAControl().name()).isEqualTo("Uso de criptografía");
        assertThat(trace.implementationGuide()).isNotNull();
        assertThat(trace.implementationGuide().id()).isEqualTo("8.24");
        assertThat(trace.implementationGuide().title()).isEqualTo("Use of cryptography");
    }

    @Test
    void getTraceability_policyWithoutImplementationGuide_omitsIt() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 1, 50);
        policy.setFramework(Framework.ISO_27001);
        policy.setControlId("A.8.24");
        policy.setImplementationGuideId(null);

        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));
        when(frameworkControlService.findControl(any(), any())).thenReturn(Optional.empty());

        var trace = policyService.getTraceability(id);

        assertThat(trace.implementationGuide()).isNull();
    }

    @Test
    void create_frameworkCategoryComboNotInCatalog_throwsBusinessValidationException() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política sin control definido",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.XSS,
            Framework.DEVSECOPS, // DEVSECOPS no cubre XSS en el catálogo
            null
        );
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(buildUser("admin")));
        when(frameworkControlService.findControl(Framework.DEVSECOPS, Category.XSS))
            .thenReturn(Optional.empty());

        assertThatThrownBy(() -> policyService.create(req, "admin"))
            .isInstanceOf(BusinessValidationException.class);

        verify(policyRepository, never()).saveAndFlush(any());
    }

    @Test
    void create_customFramework_acceptsFreeTextControlId_skipsCatalog() {
        CreatePolicyRequest req = new CreatePolicyRequest(
            "Política interna del equipo",
            "Descripción con la longitud mínima requerida de veinte caracteres.",
            Category.SQL_INJECTION,
            Framework.CUSTOM,
            "TEAM-CUSTOM-1"
        );
        User user = buildUser("admin");
        when(policyRepository.existsByNameAndFramework(any(), any())).thenReturn(false);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> inv.getArgument(0));

        PolicyResponse resp = policyService.create(req, "admin");

        assertThat(resp.controlId()).isEqualTo("TEAM-CUSTOM-1");
        verify(frameworkControlService, never()).findControl(any(), any());
    }

    // ── PATCH: campos editables, validación, historial ────────────────────

    @Test
    void patch_updatesDescriptionAndWeight_incrementsVersionAndSavesHistory() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 3, 50);
        User editor = buildUser("admin");

        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(editor));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> inv.getArgument(0));

        UpdatePolicyRequest req = new UpdatePolicyRequest(
            "Nueva descripción con longitud suficiente para pasar validación.", 90, null, null, null, null);

        PolicyResponse resp = policyService.patch(id, req, 3, "admin");

        assertThat(resp.description()).isEqualTo(req.description());
        assertThat(resp.weight()).isEqualTo(90);
        verify(policyVersionHistoryRepository).save(argThat(snapshot ->
            snapshot.getVersion() == 3 && snapshot.getWeight() == 50));
        verify(jdbcTemplate).update(contains("INSERT INTO policy_audit_log"),
            eq("POLICY_UPDATED"), eq(id), any(UUID.class), eq("admin"), anyString());
    }

    @Test
    void patch_rejectsImmutableFields_withHttp400Message() {
        UpdatePolicyRequest req = new UpdatePolicyRequest(null, null, null, "ISO_27001", null, null);

        assertThatThrownBy(() -> policyService.patch(UUID.randomUUID(), req, null, "admin"))
            .isInstanceOf(BusinessValidationException.class)
            .hasMessageContaining("no son editables");

        verifyNoInteractions(policyRepository);
    }

    @Test
    void patch_rejectsWeightOutOfRange() {
        assertThatThrownBy(() ->
            policyService.patch(UUID.randomUUID(), new UpdatePolicyRequest(null, 0, null, null, null, null), null, "admin"))
            .isInstanceOf(BusinessValidationException.class);

        assertThatThrownBy(() ->
            policyService.patch(UUID.randomUUID(), new UpdatePolicyRequest(null, -5, null, null, null, null), null, "admin"))
            .isInstanceOf(BusinessValidationException.class);

        assertThatThrownBy(() ->
            policyService.patch(UUID.randomUUID(), new UpdatePolicyRequest(null, 101, null, null, null, null), null, "admin"))
            .isInstanceOf(BusinessValidationException.class);
    }

    @Test
    void patch_staleIfMatch_throwsOptimisticLockFailure_mapsTo412() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 5, 50);
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));

        UpdatePolicyRequest req = new UpdatePolicyRequest(null, 60, null, null, null, null);

        // Client read the policy when it was at version 2; someone else has
        // since moved it to version 5 -- this must fail the same way a real
        // concurrent-write race does (ObjectOptimisticLockingFailureException
        // -> HTTP 412, per GlobalExceptionHandler).
        assertThatThrownBy(() -> policyService.patch(id, req, 2, "admin"))
            .isInstanceOf(ObjectOptimisticLockingFailureException.class);

        verify(policyRepository, never()).saveAndFlush(any());
    }

    @Test
    void patch_noActualChanges_doesNotBumpVersionOrWriteHistory() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 3, 50);
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));

        UpdatePolicyRequest req = new UpdatePolicyRequest(policy.getDescription(), policy.getWeight(), null, null, null, null);

        PolicyResponse resp = policyService.patch(id, req, 3, "admin");

        assertThat(resp.version()).isEqualTo(3);
        verify(policyVersionHistoryRepository, never()).save(any());
        verify(policyRepository, never()).saveAndFlush(any());
    }

    // ── Archivado lógico: máquina de estados ACTIVE -> ARCHIVED -> ACTIVE ──

    @Test
    void archive_movesActiveToArchived_andAudits() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 1, 50);
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));
        when(analysisRepository.findByStatusIn(anyList())).thenReturn(List.of());

        policyService.archive(id, "admin");

        assertThat(policy.getStatus()).isEqualTo(PolicyStatus.ARCHIVED);
        verify(policyRepository).saveAndFlush(policy);
        verify(jdbcTemplate).update(contains("INSERT INTO policy_audit_log"),
            eq("POLICY_ARCHIVED"), eq(id), isNull(), eq("admin"), anyString());
    }

    @Test
    void archive_blockedByInFlightAnalysis_throwsConflict409() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 1, 50);
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));

        Analysis running = new Analysis();
        running.setId(UUID.randomUUID());
        running.setStatus(AnalysisStatus.RUNNING);
        when(analysisRepository.findByStatusIn(anyList())).thenReturn(List.of(running));

        AnalysisSnapshotDto snapshot = new AnalysisSnapshotDto(
            List.of(new PolicySnapshotDto(id, policy.getName(), policy.getCategory().name(), List.of())));
        when(analysisSnapshotService.getSnapshot(running.getId())).thenReturn(snapshot);

        assertThatThrownBy(() -> policyService.archive(id, "admin"))
            .isInstanceOf(ConflictException.class)
            .hasMessageContaining("análisis en curso");

        assertThat(policy.getStatus()).isEqualTo(PolicyStatus.ACTIVE);
        verify(policyRepository, never()).saveAndFlush(any());
    }

    @Test
    void archive_notReferencedByUnrelatedInFlightAnalysis_succeeds() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 1, 50);
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));

        Analysis running = new Analysis();
        running.setId(UUID.randomUUID());
        running.setStatus(AnalysisStatus.RUNNING);
        when(analysisRepository.findByStatusIn(anyList())).thenReturn(List.of(running));

        UUID otherPolicyId = UUID.randomUUID();
        AnalysisSnapshotDto snapshot = new AnalysisSnapshotDto(
            List.of(new PolicySnapshotDto(otherPolicyId, "Otra política", "XSS", List.of())));
        when(analysisSnapshotService.getSnapshot(running.getId())).thenReturn(snapshot);

        policyService.archive(id, "admin");

        assertThat(policy.getStatus()).isEqualTo(PolicyStatus.ARCHIVED);
    }

    @Test
    void restore_movesArchivedBackToActive_andAudits() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 1, 50);
        policy.setStatus(PolicyStatus.ARCHIVED);
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> inv.getArgument(0));

        PolicyResponse resp = policyService.restore(id, "admin");

        assertThat(resp.status()).isEqualTo(PolicyStatus.ACTIVE);
        verify(jdbcTemplate).update(contains("INSERT INTO policy_audit_log"),
            eq("POLICY_RESTORED"), eq(id), isNull(), eq("admin"), anyString());
    }

    @Test
    void restore_rejectsNonArchivedPolicy() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 1, 50); // still ACTIVE
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));

        assertThatThrownBy(() -> policyService.restore(id, "admin"))
            .isInstanceOf(BusinessValidationException.class);
    }

    @Test
    void fullLifecycle_activeToArchivedToActive_preservesIdentityAndHistory() {
        UUID id = UUID.randomUUID();
        Policy policy = buildActivePolicy(id, 2, 70);
        when(policyRepository.findById(id)).thenReturn(Optional.of(policy));
        when(analysisRepository.findByStatusIn(anyList())).thenReturn(List.of());
        when(policyRepository.saveAndFlush(any(Policy.class))).thenAnswer(inv -> inv.getArgument(0));

        assertThat(policy.getStatus()).isEqualTo(PolicyStatus.ACTIVE);

        policyService.archive(id, "admin");
        assertThat(policy.getStatus()).isEqualTo(PolicyStatus.ARCHIVED);

        PolicyResponse restored = policyService.restore(id, "admin");
        assertThat(restored.status()).isEqualTo(PolicyStatus.ACTIVE);
        assertThat(restored.id()).isEqualTo(id); // same identity throughout -- never a physical delete/recreate
    }
}
