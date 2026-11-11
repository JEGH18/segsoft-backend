package co.icesi.pdgseg.service;

import org.springframework.core.io.ClassPathResource;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Directories and files that are never analyzed (default-exclusions.yml): dependencies, build
 * output, VCS metadata, caches. Used when extracting a ZIP, so a project zipped with its
 * node_modules/ or .git/ is accepted (those entries are skipped instead of counting against the
 * file limit), and by the inventory.
 */
public final class SandboxExclusions {

    private static final SandboxExclusions DEFAULT = load("default-exclusions.yml");

    private final Set<String> directoryNames;
    private final List<PathMatcher> fileMatchers;

    private SandboxExclusions(Set<String> directoryNames, List<PathMatcher> fileMatchers) {
        this.directoryNames = directoryNames;
        this.fileMatchers = fileMatchers;
    }

    public static SandboxExclusions defaults() {
        return DEFAULT;
    }

    @SuppressWarnings("unchecked")
    static SandboxExclusions load(String classpathResource) {
        try (InputStream is = new ClassPathResource(classpathResource).getInputStream()) {
            Map<String, Object> root = new Yaml().load(is);
            Map<String, Object> exclusions = (Map<String, Object>) root.get("exclusions");
            List<String> dirs = (List<String>) exclusions.get("directories");
            List<String> files = (List<String>) exclusions.get("files");

            Set<String> dirNames = dirs.stream()
                    .map(d -> d.endsWith("/") ? d.substring(0, d.length() - 1) : d)
                    .collect(Collectors.toUnmodifiableSet());
            List<PathMatcher> matchers = files.stream()
                    .map(f -> FileSystems.getDefault().getPathMatcher("glob:" + f))
                    .toList();
            return new SandboxExclusions(dirNames, matchers);
        } catch (IOException e) {
            throw new UncheckedIOException("No se pudo leer " + classpathResource, e);
        }
    }

    public Set<String> directoryNames() {
        return directoryNames;
    }

    /** Whether a path relative to the repository root ('/'-separated) must be skipped. */
    public boolean isExcluded(String relativePath) {
        String[] segments = relativePath.split("/");
        // Every segment but the last is a directory; a directory entry ("node_modules/") has
        // its own name as the last non-empty segment.
        boolean isDirectory = relativePath.endsWith("/");
        int directoryCount = isDirectory ? segments.length : segments.length - 1;
        for (int i = 0; i < directoryCount; i++) {
            if (directoryNames.contains(segments[i])) {
                return true;
            }
        }
        if (isDirectory || segments.length == 0) {
            return false;
        }
        Path fileName = Paths.get(segments[segments.length - 1]);
        for (PathMatcher matcher : fileMatchers) {
            if (matcher.matches(fileName)) {
                return true;
            }
        }
        return false;
    }

    /** Same as {@link #isExcluded(String)} for a file under {@code root}. */
    public boolean isExcluded(Path file, Path root) {
        return isExcluded(root.relativize(file).toString().replace('\\', '/'));
    }
}
