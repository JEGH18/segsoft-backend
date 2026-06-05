package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.RepositoryFile;
import co.icesi.pdgseg.entity.enums.ArtifactType;
import co.icesi.pdgseg.entity.enums.InventoryStatus;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.RepositoryFileRepository;
import co.icesi.pdgseg.repository.RepositoryRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.ClassPathResource;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

@Service
public class FileInventoryService {

    private static final Logger log = LoggerFactory.getLogger(FileInventoryService.class);

    private static final int ASYNC_THRESHOLD = 1_000;

    private static final Map<String, String> EXTENSION_TO_LANGUAGE = Map.ofEntries(
            Map.entry("java", "java"),
            Map.entry("py", "python"),
            Map.entry("pyw", "python"),
            Map.entry("js", "javascript"),
            Map.entry("jsx", "javascript"),
            Map.entry("ts", "typescript"),
            Map.entry("tsx", "typescript"),
            Map.entry("cs", "csharp"),
            Map.entry("go", "go"),
            Map.entry("rb", "ruby"),
            Map.entry("php", "php"),
            Map.entry("cpp", "cpp"),
            Map.entry("cc", "cpp"),
            Map.entry("cxx", "cpp"),
            Map.entry("c", "c"),
            Map.entry("h", "c"),
            Map.entry("hpp", "cpp"),
            Map.entry("rs", "rust"),
            Map.entry("kt", "kotlin"),
            Map.entry("swift", "swift"),
            Map.entry("xml", "xml"),
            Map.entry("json", "json"),
            Map.entry("yml", "yaml"),
            Map.entry("yaml", "yaml"),
            Map.entry("properties", "properties"),
            Map.entry("env", "env"),
            Map.entry("md", "markdown"),
            Map.entry("txt", "text"),
            Map.entry("tf", "terraform"),
            Map.entry("sql", "sql"),
            Map.entry("sh", "shell"),
            Map.entry("bash", "shell"),
            Map.entry("html", "html"),
            Map.entry("htm", "html"),
            Map.entry("css", "css"),
            Map.entry("scss", "scss"),
            Map.entry("sass", "scss"),
            Map.entry("scala", "scala"),
            Map.entry("groovy", "groovy"),
            Map.entry("r", "r"),
            Map.entry("m", "matlab"),
            Map.entry("pl", "perl"),
            Map.entry("lua", "lua"),
            Map.entry("dart", "dart")
    );

    private List<String> dirExclusionNames;
    private List<PathMatcher> fileExclusionMatchers;

    private final RepositoryRepository repositoryRepository;
    private final RepositoryFileRepository repositoryFileRepository;

    @Autowired @Lazy
    private FileInventoryService self;

    @Value("${sandbox.root:/tmp/pdgseg-sandbox}")
    private String sandboxRoot;

    public FileInventoryService(RepositoryRepository repositoryRepository,
                                RepositoryFileRepository repositoryFileRepository) {
        this.repositoryRepository = repositoryRepository;
        this.repositoryFileRepository = repositoryFileRepository;
    }

    @PostConstruct
    @SuppressWarnings("unchecked")
    void loadExclusions() throws IOException {
        ClassPathResource resource = new ClassPathResource("default-exclusions.yml");
        try (InputStream is = resource.getInputStream()) {
            Yaml yaml = new Yaml();
            Map<String, Object> root = yaml.load(is);
            Map<String, Object> exclusions = (Map<String, Object>) root.get("exclusions");

            List<String> dirs = (List<String>) exclusions.get("directories");
            List<String> files = (List<String>) exclusions.get("files");

            this.dirExclusionNames = dirs.stream()
                    .map(d -> d.endsWith("/") ? d.substring(0, d.length() - 1) : d)
                    .toList();

            FileSystem fs = FileSystems.getDefault();
            this.fileExclusionMatchers = files.stream()
                    .map(f -> fs.getPathMatcher("glob:" + f))
                    .toList();
        }
    }

    public void triggerInventory(UUID repositoryId) {
        Repository repo = repositoryRepository.findById(repositoryId)
                .orElseThrow(() -> new ResourceNotFoundException("Repository not found: " + repositoryId));

        if (repo.getPathInSandbox() == null) {
            log.warn("Repository {} has no sandbox path, skipping inventory", repositoryId);
            return;
        }

        Path sandboxPath = Paths.get(repo.getPathInSandbox());
        long fileCount = countFiles(sandboxPath);

        if (fileCount > ASYNC_THRESHOLD) {
            repo.setInventoryStatus(InventoryStatus.INVENTORYING);
            repositoryRepository.save(repo);
            self.inventoryAsync(repositoryId);
        } else {
            runInventory(repositoryId);
        }
    }

    @Async("inventoryExecutor")
    public CompletableFuture<Void> inventoryAsync(UUID repositoryId) {
        runInventory(repositoryId);
        return CompletableFuture.completedFuture(null);
    }

    public void runInventory(UUID repositoryId) {
        Repository repo = repositoryRepository.findById(repositoryId)
                .orElseThrow(() -> new ResourceNotFoundException("Repository not found: " + repositoryId));

        repo.setInventoryStatus(InventoryStatus.INVENTORYING);
        repositoryRepository.save(repo);

        try {
            Path sandboxPath = Paths.get(repo.getPathInSandbox());
            AtomicLong excludedCount = new AtomicLong(0);

            repositoryFileRepository.deleteByRepositoryId(repositoryId);

            List<RepositoryFile> files = new ArrayList<>();
            try (Stream<Path> stream = Files.walk(sandboxPath)) {
                stream.filter(Files::isRegularFile)
                        .forEach(filePath -> {
                            if (isExcluded(filePath, sandboxPath)) {
                                excludedCount.incrementAndGet();
                                return;
                            }
                            try {
                                RepositoryFile rf = buildRepositoryFile(repo, filePath, sandboxPath);
                                files.add(rf);
                            } catch (Exception e) {
                                log.warn("Skipping file {} due to error: {}", filePath, e.getMessage());
                            }
                        });
            }

            repositoryFileRepository.saveAll(files);
            repo.setInventoryStatus(InventoryStatus.READY_FOR_ANALYSIS);
            repo.setExcludedCount(excludedCount.get());
            repositoryRepository.save(repo);

            log.info("Inventory complete for repo {}: {} files indexed, {} excluded",
                    repositoryId, files.size(), excludedCount.get());

        } catch (Exception e) {
            log.error("Inventory failed for repo {}", repositoryId, e);
            repo.setInventoryStatus(InventoryStatus.FAILED);
            repositoryRepository.save(repo);
        }
    }

    private RepositoryFile buildRepositoryFile(Repository repo, Path filePath, Path sandboxPath)
            throws IOException, NoSuchAlgorithmException {

        String relativePath = sandboxPath.relativize(filePath).toString().replace('\\', '/');
        String filename = filePath.getFileName().toString();
        long sizeBytes = Files.size(filePath);
        String sha256 = computeSha256(filePath);

        RepositoryFile rf = new RepositoryFile();
        rf.setRepository(repo);
        rf.setPath(relativePath);
        rf.setLanguage(detectLanguage(filename));
        rf.setArtifactType(classifyArtifactType(filename));
        rf.setSizeBytes(sizeBytes);
        rf.setSha256(sha256);
        return rf;
    }

    boolean isExcluded(Path filePath, Path sandboxRoot) {
        Path relative = sandboxRoot.relativize(filePath);

        for (int i = 0; i < relative.getNameCount(); i++) {
            String segment = relative.getName(i).toString();
            if (dirExclusionNames.contains(segment)) {
                return true;
            }
        }

        String filename = filePath.getFileName().toString();
        for (PathMatcher matcher : fileExclusionMatchers) {
            if (matcher.matches(Paths.get(filename))) {
                return true;
            }
        }
        return false;
    }

    String detectLanguage(String filename) {
        int dotIdx = filename.lastIndexOf('.');
        if (dotIdx < 0 || dotIdx == filename.length() - 1) return "unknown";
        String ext = filename.substring(dotIdx + 1).toLowerCase(Locale.ROOT);
        return EXTENSION_TO_LANGUAGE.getOrDefault(ext, "unknown");
    }

    ArtifactType classifyArtifactType(String filename) {
        String lower = filename.toLowerCase(Locale.ROOT);

        if (lower.equals("pom.xml") || lower.equals("package.json")
                || lower.equals("requirements.txt") || lower.equals("build.gradle")
                || lower.equals("go.mod") || lower.equals("cargo.toml")
                || lower.equals("gemfile") || lower.equals("composer.json")) {
            return ArtifactType.DEPENDENCY_MANIFEST;
        }

        if (lower.equals("dockerfile") || lower.startsWith("docker-compose")
                || lower.endsWith(".tf") || lower.endsWith(".tfvars")
                || lower.equals("vagrantfile") || lower.startsWith("kubernetes")) {
            return ArtifactType.INFRASTRUCTURE_AS_CODE;
        }

        if (lower.endsWith(".yml") || lower.endsWith(".yaml")
                || lower.endsWith(".properties") || lower.endsWith(".env")
                || lower.endsWith(".ini") || lower.endsWith(".conf")
                || lower.endsWith(".cfg") || lower.endsWith(".toml")) {
            return ArtifactType.CONFIG;
        }

        if (lower.endsWith(".md") || lower.endsWith(".txt") || lower.endsWith(".rst")
                || lower.startsWith("readme") || lower.startsWith("license")
                || lower.startsWith("changelog") || lower.startsWith("contributing")) {
            return ArtifactType.DOCUMENTATION;
        }

        return ArtifactType.SOURCE_CODE;
    }

    private String computeSha256(Path file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = Files.readAllBytes(file);
        byte[] hash = digest.digest(bytes);
        return HexFormat.of().formatHex(hash);
    }

    private long countFiles(Path sandboxPath) {
        if (!Files.exists(sandboxPath)) return 0;
        try (Stream<Path> stream = Files.walk(sandboxPath)) {
            return stream.filter(Files::isRegularFile).count();
        } catch (IOException e) {
            log.warn("Could not count files in {}", sandboxPath, e);
            return 0;
        }
    }
}
