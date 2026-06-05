package co.icesi.pdgseg.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitCloneServiceTest {

    private GitCloneService service;

    @BeforeEach
    void setUp() {
        service = new GitCloneService();
        ReflectionTestUtils.setField(service, "allowedGitDomains", "github.com,gitlab.com,bitbucket.org");
    }

    // --- domain whitelist ---

    @ParameterizedTest
    @ValueSource(strings = {
            "https://github.com/user/repo.git",
            "https://gitlab.com/user/repo.git",
            "https://bitbucket.org/user/repo.git",
            "https://www.github.com/user/repo.git"
    })
    void validateDomain_allowedDomains_doesNotThrow(String url) {
        assertThatCode(() -> invokeValidateDomain(url)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://evil.com/user/repo.git",
            "https://notgithub.com/user/repo.git",
            "https://github.com.evil.org/user/repo.git"
    })
    void validateDomain_notAllowedDomain_throwsBadRequest(String url) {
        assertThatThrownBy(() -> invokeValidateDomain(url))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertStatusCode((ResponseStatusException) ex, HttpStatus.BAD_REQUEST));
    }

    @Test
    void validateDomain_malformedUrl_throwsBadRequest() {
        assertThatThrownBy(() -> invokeValidateDomain("not-a-url"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertStatusCode((ResponseStatusException) ex, HttpStatus.BAD_REQUEST));
    }

    // --- branch name validation ---

    @ParameterizedTest
    @ValueSource(strings = { "main", "develop", "feature/my-feature", "release/v1.0.0", "hotfix_123" })
    void validateBranchName_validNames_doesNotThrow(String branch) {
        assertThatCode(() -> invokeValidateBranchName(branch)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "; rm -rf /",
            "main && curl evil.com",
            "$(cat /etc/passwd)",
            "main`whoami`",
            "branch name with spaces"
    })
    void validateBranchName_shellInjectionAttempts_throwsBadRequest(String branch) {
        assertThatThrownBy(() -> invokeValidateBranchName(branch))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertStatusCode((ResponseStatusException) ex, HttpStatus.BAD_REQUEST));
    }

    @Test
    void validateBranchName_null_doesNotThrow() {
        // null branch is handled by the service (defaults to "main")
        assertThatCode(() -> invokeValidateBranchName(null)).doesNotThrowAnyException();
    }

    // --- helpers ---

    private void invokeValidateDomain(String url) {
        try {
            var method = GitCloneService.class.getDeclaredMethod("validateDomain", String.class);
            method.setAccessible(true);
            method.invoke(service, url);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void invokeValidateBranchName(String branch) {
        try {
            var method = GitCloneService.class.getDeclaredMethod("validateBranchName", String.class);
            method.setAccessible(true);
            method.invoke(service, branch);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void assertStatusCode(ResponseStatusException ex, HttpStatus expected) {
        org.assertj.core.api.Assertions.assertThat(ex.getStatusCode().value())
                .isEqualTo(expected.value());
    }
}
