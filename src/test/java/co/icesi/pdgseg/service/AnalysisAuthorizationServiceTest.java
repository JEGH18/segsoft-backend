package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.Finding;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.repository.AnalysisRepository;
import co.icesi.pdgseg.repository.FindingRepository;
import co.icesi.pdgseg.repository.RepositoryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Covers the cross-user access-denial path reported live: a DEVELOPER
 * requesting another user's analysis got an unhandled 500
 * (LazyInitializationException on repository.getUser(), thrown because
 * these methods weren't @Transactional and the session from findById()
 * had already closed by the time the lazy navigation ran) instead of a
 * clean false/403. These tests exercise the business logic; the session
 * lifecycle itself was verified live against the real database.
 */
@ExtendWith(MockitoExtension.class)
class AnalysisAuthorizationServiceTest {

    @Mock private RepositoryRepository repositoryRepository;
    @Mock private AnalysisRepository analysisRepository;
    @Mock private FindingRepository findingRepository;

    private AnalysisAuthorizationService service;

    @BeforeEach
    void setUp() {
        service = new AnalysisAuthorizationService(repositoryRepository, analysisRepository, findingRepository);
    }

    private Authentication authAs(String username, String... roles) {
        List<SimpleGrantedAuthority> authorities = List.of(roles).stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .toList();
        return new UsernamePasswordAuthenticationToken(username, "N/A", authorities);
    }

    private Repository repoOwnedBy(String username) {
        User owner = new User();
        owner.setUsername(username);
        Repository repo = new Repository();
        repo.setUser(owner);
        return repo;
    }

    // --- canAccessRepository ---

    @Test
    void canAccessRepository_owner_returnsTrue() {
        UUID repoId = UUID.randomUUID();
        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repoOwnedBy("dev")));

        assertThat(service.canAccessRepository(repoId, authAs("dev", "DEVELOPER"))).isTrue();
    }

    @Test
    void canAccessRepository_differentDeveloper_returnsFalse() {
        UUID repoId = UUID.randomUUID();
        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repoOwnedBy("admin")));

        assertThat(service.canAccessRepository(repoId, authAs("usuario", "DEVELOPER"))).isFalse();
    }

    @Test
    void canAccessRepository_auditorRole_bypassesOwnershipCheck() {
        UUID repoId = UUID.randomUUID();
        // AUDITOR short-circuits before ever touching the repository lookup.
        assertThat(service.canAccessRepository(repoId, authAs("auditor", "AUDITOR"))).isTrue();
    }

    @Test
    void canAccessRepository_unauthenticated_returnsFalse() {
        assertThat(service.canAccessRepository(UUID.randomUUID(), null)).isFalse();
    }

    @Test
    void canAccessRepository_nonExistentRepository_returnsFalse() {
        UUID repoId = UUID.randomUUID();
        when(repositoryRepository.findById(repoId)).thenReturn(Optional.empty());

        assertThat(service.canAccessRepository(repoId, authAs("usuario", "DEVELOPER"))).isFalse();
    }

    // --- canAccessAnalysis ---

    @Test
    void canAccessAnalysis_owner_returnsTrue() {
        UUID analysisId = UUID.randomUUID();
        Analysis analysis = new Analysis();
        analysis.setRepository(repoOwnedBy("dev"));
        when(analysisRepository.findById(analysisId)).thenReturn(Optional.of(analysis));

        assertThat(service.canAccessAnalysis(analysisId, authAs("dev", "DEVELOPER"))).isTrue();
    }

    @Test
    void canAccessAnalysis_differentUser_returnsFalse() {
        UUID analysisId = UUID.randomUUID();
        Analysis analysis = new Analysis();
        analysis.setRepository(repoOwnedBy("admin"));
        when(analysisRepository.findById(analysisId)).thenReturn(Optional.of(analysis));

        assertThat(service.canAccessAnalysis(analysisId, authAs("usuario", "DEVELOPER"))).isFalse();
    }

    @Test
    void canAccessAnalysis_securityAdminRole_bypassesOwnershipCheck() {
        assertThat(service.canAccessAnalysis(UUID.randomUUID(), authAs("admin", "SECURITY_ADMIN"))).isTrue();
    }

    // --- canAccessFinding ---

    @Test
    void canAccessFinding_owner_returnsTrue() {
        UUID findingId = UUID.randomUUID();
        Analysis analysis = new Analysis();
        analysis.setRepository(repoOwnedBy("dev"));
        Finding finding = new Finding();
        finding.setAnalysis(analysis);
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding));

        assertThat(service.canAccessFinding(findingId, authAs("dev", "DEVELOPER"))).isTrue();
    }

    @Test
    void canAccessFinding_differentUser_returnsFalse() {
        UUID findingId = UUID.randomUUID();
        Analysis analysis = new Analysis();
        analysis.setRepository(repoOwnedBy("admin"));
        Finding finding = new Finding();
        finding.setAnalysis(analysis);
        when(findingRepository.findById(findingId)).thenReturn(Optional.of(finding));

        assertThat(service.canAccessFinding(findingId, authAs("usuario", "DEVELOPER"))).isFalse();
    }
}
