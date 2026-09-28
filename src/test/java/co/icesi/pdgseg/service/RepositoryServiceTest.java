package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.repository.RepositoryJpaRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Covers the private-repo authentication task added to "cargar repositorio
 * para análisis": a Personal Access Token is accepted separately from
 * gitUrl, is never what gets persisted, and -- the actual security property
 * that matters -- a gitUrl with credentials embedded directly in it never
 * makes it far enough to create a Repository row at all.
 */
@ExtendWith(MockitoExtension.class)
class RepositoryServiceTest {

    @Mock private RepositoryJpaRepository repositoryRepo;
    @Mock private UserRepository userRepository;
    @Mock private ZipExtractorService zipExtractorService;
    @Mock private GitCloneService gitCloneService;

    private RepositoryService service;

    @BeforeEach
    void setUp() {
        service = new RepositoryService(repositoryRepo, userRepository, zipExtractorService, gitCloneService);
        ReflectionTestUtils.setField(service, "sandboxRoot", "/tmp/pdgseg-sandbox-test");
    }

    @Test
    void cloneGit_urlWithEmbeddedCredentials_rejectedBeforeCreatingAnyRepositoryRow() {
        String maliciousUrl = "https://ghp_secrettoken@github.com/user/private-repo.git";
        doThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "La URL no debe incluir credenciales. Para repositorios privados, use el campo de token de acceso."))
            .when(gitCloneService).validateGitUrl(maliciousUrl);

        assertThatThrownBy(() -> service.cloneGit(maliciousUrl, "main", null, "admin"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("no debe incluir credenciales");

        // The whole point: no Repository row -- not even a FAILED one -- is
        // ever created for a URL carrying a credential, so it can never end
        // up persisted anywhere, not even transiently.
        verifyNoInteractions(userRepository, repositoryRepo);
    }

    @Test
    void cloneGit_withAccessToken_passesItToGitCloneServiceButNeverStoresIt() {
        UUID userId = UUID.randomUUID();
        User user = new User();
        user.setId(userId);
        user.setUsername("admin");

        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(repositoryRepo.saveAndFlush(any())).thenAnswer(inv -> {
            Repository r = inv.getArgument(0);
            if (r.getId() == null) ReflectionTestUtils.setField(r, "id", UUID.randomUUID());
            return r;
        });
        when(repositoryRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        String cleanUrl = "https://github.com/user/private-repo.git";
        String token = "ghp_secrettoken";

        // clone() itself will fail (no real git process / sandbox in this unit
        // test) -- that's fine, the assertion is about what gets *persisted*,
        // not about a successful clone.
        doThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "El clonado falló."))
            .when(gitCloneService).clone(eq(cleanUrl), eq("main"), any(), eq(token));

        assertThatThrownBy(() -> service.cloneGit(cleanUrl, "main", token, "admin"))
            .isInstanceOf(ResponseStatusException.class);

        verify(gitCloneService).clone(eq(cleanUrl), eq("main"), any(), eq(token));

        ArgumentCaptor<Repository> captor = ArgumentCaptor.forClass(Repository.class);
        verify(repositoryRepo, atLeastOnce()).save(captor.capture());
        // gitUrl persisted is the clean, credential-free URL -- the token
        // never appears anywhere in what gets written to the database.
        assertThat(captor.getValue().getGitUrl()).isEqualTo(cleanUrl);
        assertThat(captor.getValue().getGitUrl()).doesNotContain(token);
        assertThat(captor.getValue().getErrorMessage()).doesNotContain(token);
    }
}
