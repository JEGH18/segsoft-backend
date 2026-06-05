package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.RepositoryResponse;
import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RepositoryStatus;
import co.icesi.pdgseg.entity.enums.SourceType;
import co.icesi.pdgseg.repository.RepositoryJpaRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.OffsetDateTime;
import java.util.UUID;

@Service
public class RepositoryService {

    private static final Logger log = LoggerFactory.getLogger(RepositoryService.class);

    @Value("${sandbox.root:/tmp/pdgseg-sandbox}")
    private String sandboxRoot;

    private final RepositoryJpaRepository repositoryRepo;
    private final UserRepository userRepository;
    private final ZipExtractorService zipExtractorService;
    private final GitCloneService gitCloneService;

    public RepositoryService(RepositoryJpaRepository repositoryRepo,
                              UserRepository userRepository,
                              ZipExtractorService zipExtractorService,
                              GitCloneService gitCloneService) {
        this.repositoryRepo = repositoryRepo;
        this.userRepository = userRepository;
        this.zipExtractorService = zipExtractorService;
        this.gitCloneService = gitCloneService;
    }

    @Transactional
    public RepositoryResponse uploadZip(MultipartFile file, String username) {
        User user = loadUser(username);
        Repository repo = initRepository(user, SourceType.ZIP, file.getOriginalFilename());

        Path targetDir = sandboxPath(user.getId(), repo.getId());
        try {
            ZipExtractorService.ExtractionResult result = zipExtractorService.extract(file, targetDir);
            repo.setPathInSandbox(targetDir.toString());
            repo.setSha256Archive(result.sha256());
            repo.setFileCount(result.fileCount());
            repo.setStatus(RepositoryStatus.READY_FOR_ANALYSIS);
            log.info("ZIP cargado: repoId={} files={}", repo.getId(), result.fileCount());
        } catch (ResponseStatusException e) {
            repo.setStatus(RepositoryStatus.FAILED);
            repo.setErrorMessage(e.getReason());
            repositoryRepo.save(repo);
            throw e;
        }
        return RepositoryResponse.from(repositoryRepo.save(repo));
    }

    @Transactional
    public RepositoryResponse cloneGit(String gitUrl, String branch, String username) {
        User user = loadUser(username);
        String repoName = extractRepoName(gitUrl);
        Repository repo = initRepository(user, SourceType.GIT, repoName);
        repo.setGitUrl(gitUrl);
        repo.setBranch(branch);

        Path targetDir = sandboxPath(user.getId(), repo.getId());
        try {
            gitCloneService.clone(gitUrl, branch, targetDir);
            int fileCount = countFiles(targetDir);
            repo.setPathInSandbox(targetDir.toString());
            repo.setFileCount(fileCount);
            repo.setStatus(RepositoryStatus.READY_FOR_ANALYSIS);
            log.info("Git clonado: repoId={} url={}", repo.getId(), gitUrl);
        } catch (ResponseStatusException e) {
            repo.setStatus(RepositoryStatus.FAILED);
            repo.setErrorMessage(e.getReason());
            repositoryRepo.save(repo);
            throw e;
        }
        return RepositoryResponse.from(repositoryRepo.save(repo));
    }

    @Transactional(readOnly = true)
    public RepositoryResponse findById(UUID id, String username) {
        Repository repo = repositoryRepo.findByIdAndUserUsername(id, username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Repositorio no encontrado"));
        return RepositoryResponse.from(repo);
    }

    @Transactional
    public void delete(UUID id, String username) {
        Repository repo = repositoryRepo.findByIdAndUserUsername(id, username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Repositorio no encontrado"));

        if (repo.getPathInSandbox() != null) {
            deleteDirectory(Paths.get(repo.getPathInSandbox()));
        }
        repositoryRepo.delete(repo);
    }

    @Transactional
    public void expireOldRepositories() {
        var expired = repositoryRepo.findExpired(OffsetDateTime.now());
        for (Repository repo : expired) {
            if (repo.getPathInSandbox() != null) {
                deleteDirectory(Paths.get(repo.getPathInSandbox()));
            }
            repo.setStatus(RepositoryStatus.EXPIRED);
            repositoryRepo.save(repo);
            log.info("Repositorio expirado limpiado: repoId={}", repo.getId());
        }
    }

    private Repository initRepository(User user, SourceType sourceType, String originalName) {
        Repository repo = new Repository();
        repo.setUser(user);
        repo.setSourceType(sourceType);
        repo.setOriginalName(originalName != null ? originalName : "repository");
        repo.setStatus(RepositoryStatus.UPLOADING);
        repo.setCreatedAt(OffsetDateTime.now());
        repo.setExpiresAt(OffsetDateTime.now().plusHours(24));
        return repositoryRepo.saveAndFlush(repo);
    }

    private User loadUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "Usuario no encontrado"));
    }

    private Path sandboxPath(UUID userId, UUID repoId) {
        return Paths.get(sandboxRoot, userId.toString(), repoId.toString());
    }

    private String extractRepoName(String gitUrl) {
        String[] parts = gitUrl.split("/");
        String last = parts[parts.length - 1];
        return last.endsWith(".git") ? last.substring(0, last.length() - 4) : last;
    }

    private int countFiles(Path dir) {
        try (var stream = Files.walk(dir)) {
            return (int) stream.filter(Files::isRegularFile).count();
        } catch (IOException e) {
            return 0;
        }
    }

    private void deleteDirectory(Path path) {
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
            log.warn("No se pudo eliminar directorio sandbox: {}", path, e);
        }
    }
}
