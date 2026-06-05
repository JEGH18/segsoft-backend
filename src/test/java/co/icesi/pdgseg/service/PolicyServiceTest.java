package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreatePolicyRequest;
import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.exception.PolicyConflictException;
import co.icesi.pdgseg.repository.PolicyRepository;
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

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyServiceTest {

    @Mock private PolicyRepository policyRepository;
    @Mock private UserRepository userRepository;
    @Mock private RuleRepository ruleRepository;
    @Mock private JdbcTemplate jdbcTemplate;

    private PolicyService policyService;

    @BeforeEach
    void setUp() {
        policyService = new PolicyService(policyRepository, userRepository,
                ruleRepository, jdbcTemplate, new ObjectMapper());
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
            eq("POLICY_CREATED"), any(UUID.class), eq("admin"), anyString()
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
}
