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
        validateDomain(gitUrl);
        validateBranchName(branch);

        try {
            Files.createDirectories(targetDir);
            executeClone(gitUrl, branch, targetDir);
        } catch (ResponseStatusException e) {
            deleteQuietly(targetDir);
            throw e;
        } catch (IOException e) {
            deleteQuietly(targetDir);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error al clonar el repositorio");
        }
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

    private void validateBranchName(String branch) {
        // Prevent shell injection via branch name
        if (branch != null && !branch.matches("[\\w./-]+")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nombre de branch inválido: " + branch);
        }
    }

    private void executeClone(String gitUrl, String branch, Path targetDir) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(
                "git", "clone", "--depth=1", "--branch", branch, gitUrl, targetDir.toString()
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
