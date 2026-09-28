package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.User;
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
 * Same class of bug as AnalysisAuthorizationServiceTest: canModify/canRead
 * navigate repository.getUser() (a lazy @ManyToOne) right after a plain
 * findById(), which crashed with LazyInitializationException (raw 500)
 * for any non-owner before @Transactional(readOnly = true) was added.
 */
@ExtendWith(MockitoExtension.class)
class RepositoryAuthorizationServiceTest {

    @Mock private RepositoryRepository repositoryRepository;

    private RepositoryAuthorizationService service;

    @BeforeEach
    void setUp() {
        service = new RepositoryAuthorizationService(repositoryRepository);
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

    @Test
    void canModify_owner_returnsTrue() {
        UUID repoId = UUID.randomUUID();
        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repoOwnedBy("dev")));

        assertThat(service.canModify(repoId, authAs("dev", "DEVELOPER"))).isTrue();
    }

    @Test
    void canModify_differentDeveloper_returnsFalse() {
        UUID repoId = UUID.randomUUID();
        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repoOwnedBy("admin")));

        assertThat(service.canModify(repoId, authAs("usuario", "DEVELOPER"))).isFalse();
    }

    @Test
    void canModify_securityAdmin_bypassesOwnershipCheck() {
        assertThat(service.canModify(UUID.randomUUID(), authAs("admin", "SECURITY_ADMIN"))).isTrue();
    }

    @Test
    void canModify_unauthenticated_returnsFalse() {
        assertThat(service.canModify(UUID.randomUUID(), null)).isFalse();
    }

    @Test
    void canRead_ownerOrAuditor_returnsTrue() {
        UUID repoId = UUID.randomUUID();
        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repoOwnedBy("dev")));
        assertThat(service.canRead(repoId, authAs("dev", "DEVELOPER"))).isTrue();

        // AUDITOR bypasses ownership entirely, no lookup needed.
        assertThat(service.canRead(UUID.randomUUID(), authAs("auditor", "AUDITOR"))).isTrue();
    }

    @Test
    void canRead_differentDeveloper_returnsFalse() {
        UUID repoId = UUID.randomUUID();
        when(repositoryRepository.findById(repoId)).thenReturn(Optional.of(repoOwnedBy("admin")));

        assertThat(service.canRead(repoId, authAs("usuario", "DEVELOPER"))).isFalse();
    }
}
