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
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class GitCloneService {

    private static final Logger log = LoggerFactory.getLogger(GitCloneService.class);

    @Value("${sandbox.allowed-git-domains:github.com,gitlab.com,bitbucket.org,pi2tools.icesi.edu.co}")
    private String allowedGitDomains;

    /** Self-hosted Bitbucket Server / Data Center hosts (e.g. p2tools), which take the token as a Bearer header. */
    @Value("${sandbox.bitbucket-server-hosts:pi2tools.icesi.edu.co}")
    private String bitbucketServerHosts;

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

        if (!matchesAnyDomain(host, allowedGitDomains)) {
            log.warn("Intento de clonar desde dominio no permitido: {}", host);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Dominio Git no permitido: " + host + ". Dominios permitidos: " + allowedGitDomains);
        }
    }

    private static boolean matchesAnyDomain(String host, String domains) {
        List<String> list = Arrays.asList(domains.split(","));
        return list.stream()
                .map(String::trim)
                .filter(d -> !d.isEmpty())
                .anyMatch(d -> host.equals(d) || host.endsWith("." + d));
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
        // English messages, so classifyFailure can recognize them whatever the server locale is.
        pb.environment().put("LC_ALL", "C");
        pb.environment().put("LANG", "C");
        pb.environment().putAll(authHeaderEnvironment(gitUrl, accessToken));
        pb.redirectErrorStream(true);
        // To a file rather than a pipe: nothing has to drain it while git runs.
        Path output = Files.createTempFile("git-clone-", ".log");
        pb.redirectOutput(output.toFile());

        try {
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
                String gitOutput = readTail(output);
                // git can echo the clone URL, token included: only a redacted copy reaches the log,
                // and the user gets a fixed message, never git's own text.
                log.warn("git clone falló: url={} rama={} salida={}",
                        gitUrl, branch, redact(gitOutput, accessToken));
                boolean withToken = accessToken != null && !accessToken.isBlank();
                throw classifyFailure(gitOutput, branch, hostOf(gitUrl), withToken, isBitbucketServer(hostOf(gitUrl)));
            }
        } finally {
            Files.deleteIfExists(output);
        }
    }

    private static final int MAX_OUTPUT_CHARS = 4000;

    private static String readTail(Path file) {
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            return text.length() > MAX_OUTPUT_CHARS ? text.substring(text.length() - MAX_OUTPUT_CHARS) : text;
        } catch (IOException e) {
            return "";
        }
    }

    /** Removes the token (raw and URL-encoded) and any user:password@ from git's output. */
    static String redact(String output, String accessToken) {
        String result = output.replaceAll("://[^/@\\s]+@", "://***@");
        if (accessToken != null && !accessToken.isBlank()) {
            String token = accessToken.trim();
            result = result.replace(token, "***")
                    .replace(URLEncoder.encode(token, StandardCharsets.UTF_8), "***");
        }
        return result.strip();
    }

    private static String hostOf(String gitUrl) {
        try {
            return new URL(gitUrl).getHost();
        } catch (MalformedURLException e) {
            return "";
        }
    }

    /**
     * Turns git's output into a message the user can act on. Patterns come from git 2.x's own
     * messages (forced to English with LC_ALL=C). With GIT_TERMINAL_PROMPT=0, a server that
     * answers 401 makes git fail with "could not read Username/Password".
     */
    static ResponseStatusException classifyFailure(String gitOutput, String branch, String host,
                                                   boolean withToken, boolean bitbucketServer) {
        String out = gitOutput == null ? "" : gitOutput.toLowerCase();
        String where = host == null || host.isBlank() ? "el servidor Git" : host;

        if (out.contains("not found in upstream") || out.contains("could not find remote branch")) {
            return new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "La rama \"" + branch + "\" no existe en el repositorio. Revise el nombre (por ejemplo, main o master).");
        }
        if (out.contains("could not resolve host") || out.contains("failed to connect")
                || out.contains("couldn't connect") || out.contains("connection timed out")
                || out.contains("connection refused") || out.contains("network is unreachable")
                || out.contains("operation timed out") || out.contains("connection reset")) {
            return new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "El servidor de SegSoft no pudo conectarse con " + where
                            + ". Intente más tarde o suba el proyecto como archivo ZIP.");
        }
        if (out.contains("ssl certificate") || out.contains("certificate verif") || out.contains("ssl_")
                || out.contains("openssl") || out.contains("gnutls") || out.contains("tls connect")
                || out.contains("schannel")) {
            return new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "No se pudo establecer una conexión segura con " + where
                            + " (problema con su certificado). Intente más tarde o suba el proyecto como archivo ZIP.");
        }
        if (out.contains("returned error: 403")) {
            return new ResponseStatusException(HttpStatus.BAD_REQUEST, withToken
                    ? "El token fue aceptado, pero no tiene permiso de lectura sobre este repositorio."
                    : "El servidor negó el acceso al repositorio. Si es privado, proporcione un token de acceso con permiso de lectura.");
        }
        if (out.contains("returned error: 404") || out.contains("repository not found")
                || (out.contains("repository '") && out.contains("not found"))) {
            return new ResponseStatusException(HttpStatus.BAD_REQUEST, withToken
                    ? "No se encontró el repositorio, o el token no tiene acceso a él. Revise la URL y los permisos del token."
                    : "No se encontró el repositorio. Revise la URL; si es privado, proporcione un token de acceso.");
        }
        if (out.contains("could not read username") || out.contains("could not read password")
                || out.contains("authentication failed") || out.contains("returned error: 401")
                || out.contains("invalid credentials") || out.contains("access denied")
                || out.contains("invalid username or")) {
            if (!withToken) {
                return new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "El repositorio es privado o no existe. Si es privado, proporcione un token de acceso con permiso de lectura.");
            }
            String message = "El servidor rechazó el token de acceso, o el repositorio no existe. "
                    + "Revise la URL y que el token esté completo y no haya vencido.";
            if (bitbucketServer) {
                message += " En p2tools debe ser un token HTTP de acceso (Administrar cuenta → Tokens de acceso HTTP)"
                        + " con permiso de lectura; la contraseña de la cuenta no sirve.";
            }
            return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
        }
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, withToken
                ? "El clonado falló. Verifique que la URL y la rama sean correctas y que el token tenga permiso de lectura sobre el repositorio."
                : "El clonado falló. Verifique que la URL y la rama sean correctas. Si el repositorio es privado, proporcione un token de acceso.");
    }

    /**
     * Injects the token as URL userinfo. Built fresh for this one process
     * invocation only -- never returned, logged, or stored.
     */
    private String buildAuthenticatedUrl(String gitUrl, String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return gitUrl;
        }
        try {
            URL url = new URL(gitUrl);
            if (isBitbucketServer(url.getHost())) {
                return gitUrl; // the token goes in a header instead, see authHeaderEnvironment
            }
            String encodedToken = URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
            int port = url.getPort();
            return url.getProtocol() + "://" + userInfoFor(url.getHost(), encodedToken) + "@" + url.getHost()
                    + (port != -1 ? ":" + port : "")
                    + url.getPath()
                    + (url.getQuery() != null ? "?" + url.getQuery() : "");
        } catch (MalformedURLException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL Git inválida: " + gitUrl);
        }
    }

    /**
     * GitHub accepts the token as the username with an empty password
     * (TOKEN@host). Bitbucket Cloud rejects that: it needs the fixed username
     * "x-token-auth" with the token as password, which works for repository,
     * project and workspace access tokens as well as Atlassian API tokens.
     */
    private String userInfoFor(String host, String encodedToken) {
        String h = host.toLowerCase();
        if (h.equals("bitbucket.org") || h.endsWith(".bitbucket.org")) {
            return "x-token-auth:" + encodedToken;
        }
        return encodedToken;
    }

    /**
     * Bitbucket Server / Data Center HTTP access tokens: project and repository
     * tokens only work as "Authorization: Bearer", never in Basic auth, and
     * personal tokens accept Bearer too. Git reads the header from GIT_CONFIG_*
     * variables, scoped to the repository's host, so the token stays out of the
     * process arguments and out of the cloned repository's .git/config.
     */
    private Map<String, String> authHeaderEnvironment(String gitUrl, String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return Map.of();
        }
        URL url;
        try {
            url = new URL(gitUrl);
        } catch (MalformedURLException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL Git inválida: " + gitUrl);
        }
        if (!isBitbucketServer(url.getHost())) {
            return Map.of();
        }
        String token = accessToken.trim();
        // Printable ASCII only: a CR/LF would let the token inject extra headers.
        if (!token.matches("[\\x21-\\x7E]+")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El token de acceso contiene caracteres no válidos.");
        }
        int port = url.getPort();
        String hostScope = url.getProtocol() + "://" + url.getHost() + (port != -1 ? ":" + port : "") + "/";
        return Map.of(
                "GIT_CONFIG_COUNT", "1",
                "GIT_CONFIG_KEY_0", "http." + hostScope + ".extraHeader",
                "GIT_CONFIG_VALUE_0", "Authorization: Bearer " + token);
    }

    private boolean isBitbucketServer(String host) {
        return matchesAnyDomain(host.toLowerCase(), bitbucketServerHosts);
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
