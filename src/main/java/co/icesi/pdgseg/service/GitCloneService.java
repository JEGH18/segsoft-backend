package co.icesi.pdgseg.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class GitCloneService {

    private static final Logger log = LoggerFactory.getLogger(GitCloneService.class);

    @Value("${sandbox.allowed-git-domains:github.com,gitlab.com,bitbucket.org}")
    private String allowedGitDomains;

    private static final int CLONE_TIMEOUT_SECONDS = 120;

    public void clone(String gitUrl, String branch, Path targetDir) {
        clone(gitUrl, branch, targetDir, null);
    }

    /**
     * accessToken is optional and only needed for private repositories. It is
     * used once to build the URL handed to the "git clone" process and is
     * never logged, never persisted, and never present in gitUrl itself
     * (rejectEmbeddedCredentials enforces that the caller uses this
     * parameter instead of pasting a token directly into the URL).
     */
    public void clone(String gitUrl, String branch, Path targetDir, String accessToken) {
        validateGitUrl(gitUrl);
        validateBranchName(branch);

        try {
            Files.createDirectories(targetDir);
            executeClone(gitUrl, branch, targetDir, accessToken);
        } catch (ResponseStatusException e) {
            deleteQuietly(targetDir);
            throw e;
        } catch (IOException e) {
            deleteQuietly(targetDir);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error al clonar el repositorio");
        }
    }

    /**
     * Exposed so callers (RepositoryService) can validate -- and reject a
     * credential-bearing gitUrl -- BEFORE writing it into an entity that
     * might get persisted on a later failure path. clone() also runs this
     * itself, so calling it standalone first is optional, not required.
     */
    public void validateGitUrl(String gitUrl) {
        validateDomain(gitUrl);
        rejectEmbeddedCredentials(gitUrl);
    }

    private void validateDomain(String gitUrl) {
        String host;
        try {
            host = new URL(gitUrl).getHost().toLowerCase();
        } catch (MalformedURLException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL Git inválida: " + gitUrl);
        }

        List<String> allowed = Arrays.asList(allowedGitDomains.split(","));
        boolean permitted = allowed.stream()
                .map(String::trim)
                .anyMatch(d -> host.equals(d) || host.endsWith("." + d));

        if (!permitted) {
            log.warn("Intento de clonar desde dominio no permitido: {}", host);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Dominio Git no permitido: " + host + ". Dominios permitidos: " + allowedGitDomains);
        }
    }

    /**
     * A URL like https://TOKEN@github.com/... would get persisted verbatim
     * in Repository.gitUrl and logged in RepositoryService -- reject it up
     * front instead of trying to scrub it after the fact. Callers with a
     * private repo must use the separate accessToken parameter.
     */
    private void rejectEmbeddedCredentials(String gitUrl) {
        String userInfo;
        try {
            userInfo = new URL(gitUrl).getUserInfo();
        } catch (MalformedURLException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL Git inválida: " + gitUrl);
        }
        if (userInfo != null && !userInfo.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "La URL no debe incluir credenciales. Para repositorios privados, use el campo de token de acceso.");
        }
    }

    private void validateBranchName(String branch) {
        // Prevent shell injection via branch name
        if (branch != null && !branch.matches("[\\w./-]+")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nombre de branch inválido: " + branch);
        }
    }

    private void executeClone(String gitUrl, String branch, Path targetDir, String accessToken) throws IOException {
        String cloneUrl = buildAuthenticatedUrl(gitUrl, accessToken);
        ProcessBuilder pb = new ProcessBuilder(
                "git", "clone", "--depth=1", "--branch", branch, cloneUrl, targetDir.toString()
        );
        pb.environment().put("GIT_TERMINAL_PROMPT", "0");
        pb.redirectErrorStream(true);

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "No se pudo ejecutar git clone");
        }

        boolean finished;
        try {
            finished = process.waitFor(CLONE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Clonado interrumpido");
        }

        if (!finished) {
            process.destroyForcibly();
            throw new ResponseStatusException(HttpStatus.REQUEST_TIMEOUT,
                    "Timeout al clonar el repositorio (límite: " + CLONE_TIMEOUT_SECONDS + "s)");
        }

        if (process.exitValue() != 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El clonado falló. Verifique que la URL y la rama sean correctas y que el repositorio sea público.");
        }
    }

    /**
     * Injects the token as URL userinfo (the form every major Git host
     * accepts over HTTPS: https://TOKEN@host/...). Built fresh for this one
     * process invocation only -- never returned, logged, or stored.
     */
    private String buildAuthenticatedUrl(String gitUrl, String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return gitUrl;
        }
        try {
            URL url = new URL(gitUrl);
            String encodedToken = URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            int port = url.getPort();
            return url.getProtocol() + "://" + encodedToken + "@" + url.getHost()
                    + (port != -1 ? ":" + port : "")
                    + url.getPath()
                    + (url.getQuery() != null ? "?" + url.getQuery() : "");
        } catch (MalformedURLException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL Git inválida: " + gitUrl);
        }
    }

    private void deleteQuietly(Path path) {
        try {
            if (Files.exists(path)) {
                try (var walk = Files.walk(path)) {
                    walk.sorted(java.util.Comparator.reverseOrder())
                        .forEach(p -> {
                            try { Files.delete(p); } catch (IOException ignored) {}
                        });
                }
            }
        } catch (IOException e) {
            log.warn("No se pudo limpiar directorio temporal: {}", path, e);
        }
    }
}
