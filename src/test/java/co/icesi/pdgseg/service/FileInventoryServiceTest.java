package co.icesi.pdgseg.service;

import co.icesi.pdgseg.entity.enums.ArtifactType;
import co.icesi.pdgseg.repository.RepositoryFileRepository;
import co.icesi.pdgseg.repository.RepositoryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class FileInventoryServiceTest {

    @Mock
    private RepositoryRepository repositoryRepository;
    @Mock
    private RepositoryFileRepository repositoryFileRepository;

    private FileInventoryService service;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() throws IOException {
        service = new FileInventoryService(repositoryRepository, repositoryFileRepository);
        service.loadExclusions();
    }

    // ── Language detection ────────────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
            "Main.java,     java",
            "app.py,        python",
            "script.pyw,    python",
            "index.js,      javascript",
            "App.tsx,       typescript",
            "main.go,       go",
            "lib.rs,        rust",
            "Main.kt,       kotlin",
            "App.swift,     swift",
            "styles.css,    css",
            "config.yml,    yaml",
            "data.json,     json",
            "README.md,     markdown",
            "Makefile,      unknown",
            "noextension,   unknown"
    })
    void detectLanguage_returnsExpectedLanguage(String filename, String expected) {
        assertThat(service.detectLanguage(filename.trim())).isEqualTo(expected.trim());
    }

    @Test
    void detectLanguage_unicodeFilename_returnsUnknown() {
        assertThat(service.detectLanguage("データ処理")).isEqualTo("unknown");
    }

    @Test
    void detectLanguage_unicodeFilenameWithJavaExtension_returnsJava() {
        assertThat(service.detectLanguage("クラス.java")).isEqualTo("java");
    }

    // ── Artifact type classification ──────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
            "pom.xml,               DEPENDENCY_MANIFEST",
            "package.json,          DEPENDENCY_MANIFEST",
            "requirements.txt,      DEPENDENCY_MANIFEST",
            "build.gradle,          DEPENDENCY_MANIFEST",
            "go.mod,                DEPENDENCY_MANIFEST",
            "Dockerfile,            INFRASTRUCTURE_AS_CODE",
            "docker-compose.yml,    INFRASTRUCTURE_AS_CODE",
            "main.tf,               INFRASTRUCTURE_AS_CODE",
            "application.yml,       CONFIG",
            "app.yaml,              CONFIG",
            "database.properties,   CONFIG",
            ".env,                  CONFIG",
            "README.md,             DOCUMENTATION",
            "README.txt,            DOCUMENTATION",
            "CHANGELOG.md,          DOCUMENTATION",
            "Main.java,             SOURCE_CODE",
            "service.py,            SOURCE_CODE",
            "index.ts,              SOURCE_CODE"
    })
    void classifyArtifactType_returnsExpectedType(String filename, ArtifactType expected) {
        assertThat(service.classifyArtifactType(filename.trim())).isEqualTo(expected);
    }

    // ── Exclusion engine ──────────────────────────────────────────────────────

    @Test
    void isExcluded_fileInTargetDirectory_returnsTrue() throws IOException {
        Path targetDir = tempDir.resolve("target");
        Files.createDirectory(targetDir);
        Path file = targetDir.resolve("Main.class");
        Files.createFile(file);

        assertThat(service.isExcluded(file, tempDir)).isTrue();
    }

    @Test
    void isExcluded_fileInNodeModules_returnsTrue() throws IOException {
        Path nodeModules = tempDir.resolve("node_modules");
        Files.createDirectory(nodeModules);
        Path file = nodeModules.resolve("lodash.js");
        Files.createFile(file);

        assertThat(service.isExcluded(file, tempDir)).isTrue();
    }

    @Test
    void isExcluded_fileInNestedExcludedDir_returnsTrue() throws IOException {
        Path src = tempDir.resolve("src");
        Files.createDirectory(src);
        Path pycache = src.resolve("__pycache__");
        Files.createDirectory(pycache);
        Path file = pycache.resolve("module.pyc");
        Files.createFile(file);

        assertThat(service.isExcluded(file, tempDir)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"bundle.min.js", "vendor.min.js", "script.pyc", "Main.class"})
    void isExcluded_excludedFilePattern_returnsTrue(String filename) throws IOException {
        Path file = tempDir.resolve(filename);
        Files.createFile(file);

        assertThat(service.isExcluded(file, tempDir)).isTrue();
    }

    @Test
    void isExcluded_normalSourceFile_returnsFalse() throws IOException {
        Path src = tempDir.resolve("src");
        Files.createDirectory(src);
        Path file = src.resolve("Main.java");
        Files.writeString(file, "public class Main {}", StandardCharsets.UTF_8);

        assertThat(service.isExcluded(file, tempDir)).isFalse();
    }

    @Test
    void isExcluded_gitDirectory_returnsTrue() throws IOException {
        Path gitDir = tempDir.resolve(".git");
        Files.createDirectory(gitDir);
        Path file = gitDir.resolve("config");
        Files.createFile(file);

        assertThat(service.isExcluded(file, tempDir)).isTrue();
    }

    @Test
    void isExcluded_unicodeFilename_normalPath_returnsFalse() throws IOException {
        Path file = tempDir.resolve("データ.java");
        Files.writeString(file, "// unicode", StandardCharsets.UTF_8);

        assertThat(service.isExcluded(file, tempDir)).isFalse();
    }

    // ── SHA-256 correctness is verified implicitly via buildRepositoryFile ────
}
