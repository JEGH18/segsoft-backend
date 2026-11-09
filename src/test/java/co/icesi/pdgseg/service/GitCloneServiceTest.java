package co.icesi.pdgseg.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class GitCloneServiceTest {

    private GitCloneService service;

    @BeforeEach
    void setUp() {
        service = new GitCloneService();
        ReflectionTestUtils.setField(service, "allowedGitDomains",
                "github.com,gitlab.com,bitbucket.org,pi2tools.icesi.edu.co");
        ReflectionTestUtils.setField(service, "bitbucketServerHosts", "pi2tools.icesi.edu.co");
    }

    // --- domain whitelist ---

    @ParameterizedTest
    @ValueSource(strings = {
            "https://github.com/user/repo.git",
            "https://gitlab.com/user/repo.git",
            "https://bitbucket.org/user/repo.git",
            "https://www.github.com/user/repo.git",
            "https://pi2tools.icesi.edu.co/bitbucket/scm/segsoft/segsoft-backend.git"
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

    // --- embedded credentials rejection (private-repo auth task) ---

    @ParameterizedTest
    @ValueSource(strings = {
            "https://ghp_secrettoken@github.com/user/repo.git",
            "https://user:password@gitlab.com/user/repo.git",
            "https://x-token-auth:token123@bitbucket.org/user/repo.git"
    })
    void validateGitUrl_urlWithEmbeddedCredentials_throwsBadRequest(String url) {
        assertThatThrownBy(() -> service.validateGitUrl(url))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("no debe incluir credenciales")
                .satisfies(ex -> assertStatusCode((ResponseStatusException) ex, HttpStatus.BAD_REQUEST));
    }

    @Test
    void validateGitUrl_cleanUrl_doesNotThrow() {
        assertThatCode(() -> service.validateGitUrl("https://github.com/user/repo.git"))
                .doesNotThrowAnyException();
    }

    // --- ephemeral token injection for private repos ---

    @Test
    void buildAuthenticatedUrl_withToken_injectsItAsUserInfo() {
        String result = invokeBuildAuthenticatedUrl("https://github.com/user/repo.git", "ghp_secrettoken");
        org.assertj.core.api.Assertions.assertThat(result)
                .isEqualTo("https://ghp_secrettoken@github.com/user/repo.git");
    }

    @Test
    void buildAuthenticatedUrl_bitbucket_usesXTokenAuthUsernameWithTokenAsPassword() {
        String result = invokeBuildAuthenticatedUrl("https://bitbucket.org/pi2tools/repo.git", "bbtoken123");
        org.assertj.core.api.Assertions.assertThat(result)
                .isEqualTo("https://x-token-auth:bbtoken123@bitbucket.org/pi2tools/repo.git");
    }

    @Test
    void buildAuthenticatedUrl_bitbucketHostIsCaseInsensitive() {
        String result = invokeBuildAuthenticatedUrl("https://BitBucket.org/pi2tools/repo.git", "bbtoken123");
        org.assertj.core.api.Assertions.assertThat(result).contains("x-token-auth:bbtoken123@");
    }

    @Test
    void buildAuthenticatedUrl_atlassianApiTokenWithEqualsSign_isEncodedInsidePasswordPart() {
        // Atlassian API tokens end in "=XXXXXXXX"; it must stay inside the password, URL-encoded.
        String result = invokeBuildAuthenticatedUrl("https://bitbucket.org/pi2tools/repo.git", "ATATT3xFf=AB12");
        org.assertj.core.api.Assertions.assertThat(result)
                .isEqualTo("https://x-token-auth:ATATT3xFf%3DAB12@bitbucket.org/pi2tools/repo.git");
    }

    @Test
    void buildAuthenticatedUrl_lookalikeBitbucketDomain_doesNotGetBitbucketUsername() {
        String result = invokeBuildAuthenticatedUrl("https://notbitbucket.org/user/repo.git", "tok");
        org.assertj.core.api.Assertions.assertThat(result).isEqualTo("https://tok@notbitbucket.org/user/repo.git");
    }

    @Test
    void buildAuthenticatedUrl_withoutToken_returnsUrlUnchanged() {
        String result = invokeBuildAuthenticatedUrl("https://github.com/user/repo.git", null);
        org.assertj.core.api.Assertions.assertThat(result).isEqualTo("https://github.com/user/repo.git");
    }

    @Test
    void buildAuthenticatedUrl_tokenWithSpecialCharacters_getsUrlEncoded() {
        // A token containing '@' or '/' must not break the resulting URL's structure.
        String result = invokeBuildAuthenticatedUrl("https://github.com/user/repo.git", "tok@en/with special");
        org.assertj.core.api.Assertions.assertThat(result)
                .startsWith("https://")
                .contains("@github.com/user/repo.git")
                .doesNotContain("tok@en/with special"); // raw token never appears verbatim
    }

    // --- Bitbucket Server / Data Center (p2tools): token as a Bearer header ---

    private static final String P2TOOLS_REPO = "https://pi2tools.icesi.edu.co/bitbucket/scm/segsoft/segsoft-backend.git";

    @Test
    void buildAuthenticatedUrl_bitbucketServer_keepsTokenOutOfTheUrl() {
        String result = invokeBuildAuthenticatedUrl(P2TOOLS_REPO, "BBDC-secret");
        org.assertj.core.api.Assertions.assertThat(result).isEqualTo(P2TOOLS_REPO);
    }

    @Test
    void authHeaderEnvironment_bitbucketServer_sendsBearerHeaderScopedToTheHost() {
        Map<String, String> env = invokeAuthHeaderEnvironment(P2TOOLS_REPO, "BBDC-secret");
        org.assertj.core.api.Assertions.assertThat(env).containsExactlyInAnyOrderEntriesOf(Map.of(
                "GIT_CONFIG_COUNT", "1",
                "GIT_CONFIG_KEY_0", "http.https://pi2tools.icesi.edu.co/.extraHeader",
                "GIT_CONFIG_VALUE_0", "Authorization: Bearer BBDC-secret"));
    }

    @Test
    void authHeaderEnvironment_bitbucketServerWithPort_includesThePortInTheScope() {
        Map<String, String> env = invokeAuthHeaderEnvironment(
                "https://pi2tools.icesi.edu.co:8443/scm/segsoft/repo.git", "tok");
        org.assertj.core.api.Assertions.assertThat(env)
                .containsEntry("GIT_CONFIG_KEY_0", "http.https://pi2tools.icesi.edu.co:8443/.extraHeader");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://github.com/user/repo.git",
            "https://bitbucket.org/pi2tools/repo.git",
            "https://pi2tools.icesi.edu.co.evil.com/scm/segsoft/repo.git"
    })
    void authHeaderEnvironment_otherHosts_addsNoHeader(String url) {
        org.assertj.core.api.Assertions.assertThat(invokeAuthHeaderEnvironment(url, "tok")).isEmpty();
    }

    @Test
    void authHeaderEnvironment_withoutToken_addsNoHeader() {
        org.assertj.core.api.Assertions.assertThat(invokeAuthHeaderEnvironment(P2TOOLS_REPO, null)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = { "tok\r\nX-Injected: 1", "tok en" })
    void authHeaderEnvironment_tokenWithControlCharsOrSpaces_throwsBadRequest(String token) {
        assertThatThrownBy(() -> invokeAuthHeaderEnvironment(P2TOOLS_REPO, token))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("caracteres no válidos")
                .hasMessageNotContaining(token)
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

    // --- failure messages from git's output (samples are real git 2.x output) ---

    private static final String P2TOOLS_HOST = "pi2tools.icesi.edu.co";

    @Test
    void classifyFailure_missingBranch_namesTheBranch() {
        var ex = GitCloneService.classifyFailure(
                "Cloning into 'out'...\nfatal: Remote branch nope not found in upstream origin\n",
                "nope", "github.com", false, false);
        assertStatusCode(ex, HttpStatus.BAD_REQUEST);
        assertThat(ex.getReason()).contains("La rama \"nope\" no existe");
    }

    @Test
    void classifyFailure_unknownHost_saysTheServerCouldNotConnect() {
        var ex = GitCloneService.classifyFailure(
                "fatal: unable to access 'https://x.invalid/y.git/': Could not resolve host: x.invalid",
                "main", "x.invalid", false, false);
        assertStatusCode(ex, HttpStatus.BAD_GATEWAY);
        assertThat(ex.getReason()).contains("no pudo conectarse con x.invalid");
    }

    @Test
    void classifyFailure_connectTimeout_saysTheServerCouldNotConnect() {
        var ex = GitCloneService.classifyFailure(
                "fatal: unable to access 'https://h/r.git/': Failed to connect to h port 443 after 130000 ms: Couldn't connect to server",
                "main", "h", true, true);
        assertStatusCode(ex, HttpStatus.BAD_GATEWAY);
    }

    @Test
    void classifyFailure_badCertificate_saysSecureConnectionFailed() {
        var ex = GitCloneService.classifyFailure(
                "fatal: unable to access 'https://h/r.git/': SSL certificate problem: unable to get local issuer certificate",
                "main", "h", false, false);
        assertStatusCode(ex, HttpStatus.BAD_GATEWAY);
        assertThat(ex.getReason()).contains("conexión segura");
    }

    @Test
    void classifyFailure_p2toolsRejectsTheBearerToken_explainsWhichTokenToUse() {
        var ex = GitCloneService.classifyFailure(
                "fatal: could not read Username for 'https://pi2tools.icesi.edu.co': terminal prompts disabled",
                "main", P2TOOLS_HOST, true, true);
        assertStatusCode(ex, HttpStatus.BAD_REQUEST);
        assertThat(ex.getReason())
                .contains("rechazó el token")
                .contains("token HTTP de acceso")
                .contains("la contraseña de la cuenta no sirve");
    }

    @Test
    void classifyFailure_githubRejectsTheToken_saysTheTokenWasRejectedWithoutP2toolsHint() {
        var ex = GitCloneService.classifyFailure(
                "fatal: could not read Password for 'https://***@github.com': terminal prompts disabled",
                "main", "github.com", true, false);
        assertThat(ex.getReason()).contains("rechazó el token").doesNotContain("p2tools");
    }

    @Test
    void classifyFailure_bitbucketCloudAuthenticationFailed_saysTheTokenWasRejected() {
        var ex = GitCloneService.classifyFailure(
                "remote: You may not have access to this repository or it no longer exists in this workspace.\n"
                        + "fatal: Authentication failed for 'https://bitbucket.org/a/b.git/'",
                "main", "bitbucket.org", true, false);
        assertThat(ex.getReason()).contains("rechazó el token");
    }

    @Test
    void classifyFailure_privateRepoWithoutToken_asksForAToken() {
        var ex = GitCloneService.classifyFailure(
                "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
                "main", "github.com", false, false);
        assertThat(ex.getReason()).contains("privado o no existe").contains("proporcione un token");
    }

    @Test
    void classifyFailure_forbidden_saysTheTokenLacksReadPermission() {
        var ex = GitCloneService.classifyFailure(
                "fatal: unable to access 'https://h/r.git/': The requested URL returned error: 403",
                "main", "h", true, true);
        assertThat(ex.getReason()).contains("no tiene permiso de lectura");
    }

    @Test
    void classifyFailure_repositoryNotFound_asksToCheckTheUrl() {
        var ex = GitCloneService.classifyFailure(
                "fatal: repository 'https://pi2tools.icesi.edu.co/bitbucket/scm/segsoft/x.git/' not found",
                "main", P2TOOLS_HOST, true, true);
        assertThat(ex.getReason()).contains("No se encontró el repositorio");
    }

    @Test
    void classifyFailure_unknownOutput_fallsBackToTheGenericMessage() {
        var ex = GitCloneService.classifyFailure("fatal: something unexpected", "main", "h", false, false);
        assertStatusCode(ex, HttpStatus.BAD_REQUEST);
        assertThat(ex.getReason()).startsWith("El clonado falló");
    }

    @Test
    void redact_removesTheTokenAndAnyUserinfo() {
        String out = "fatal: could not read Password for 'https://ghp_secret@github.com': x\n"
                + "fatal: Authentication failed for 'https://x-token-auth:ATATT%3DAB@bitbucket.org/a.git/'\n"
                + "token ATATT=AB again";
        assertThat(GitCloneService.redact(out, "ATATT=AB"))
                .doesNotContain("ghp_secret")
                .doesNotContain("ATATT")
                .contains("https://***@github.com");
    }

    @Test
    void clone_missingBranchOnARealRepository_reportsTheBranch(@TempDir Path tmp) throws Exception {
        assumeTrue(gitAvailable(), "git no está instalado");
        Path bare = tmp.resolve("origin.git");
        run(tmp, "git", "init", "-q", "--bare", bare.toString());
        Path work = tmp.resolve("work");
        run(tmp, "git", "init", "-q", work.toString());
        run(work, "git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x");
        run(work, "git", "push", "-q", bare.toUri().toString(), "HEAD:refs/heads/main");

        // executeClone skips the domain check, so a local file:// repository can stand in for a server.
        assertThatThrownBy(() -> invokeExecuteClone(bare.toUri().toString(), "no-existe", tmp.resolve("out")))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("La rama \"no-existe\" no existe");
    }

    private static boolean gitAvailable() {
        try {
            return new ProcessBuilder("git", "--version").start().waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static void run(Path dir, String... command) throws Exception {
        Process p = new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new IllegalStateException(String.join(" ", command) + ": " + out);
    }

    private void invokeExecuteClone(String url, String branch, Path target) {
        try {
            var method = GitCloneService.class.getDeclaredMethod(
                    "executeClone", String.class, String.class, Path.class, String.class);
            method.setAccessible(true);
            method.invoke(service, url, branch, target, null);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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

    private String invokeBuildAuthenticatedUrl(String gitUrl, String accessToken) {
        try {
            var method = GitCloneService.class.getDeclaredMethod("buildAuthenticatedUrl", String.class, String.class);
            method.setAccessible(true);
            return (String) method.invoke(service, gitUrl, accessToken);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> invokeAuthHeaderEnvironment(String gitUrl, String accessToken) {
        try {
            var method = GitCloneService.class.getDeclaredMethod("authHeaderEnvironment", String.class, String.class);
            method.setAccessible(true);
            return (Map<String, String>) method.invoke(service, gitUrl, accessToken);
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
