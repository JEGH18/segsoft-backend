package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.RepositoryFile;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.ArtifactType;
import co.icesi.pdgseg.entity.enums.InventoryStatus;
import co.icesi.pdgseg.entity.enums.RepositoryStatus;
import co.icesi.pdgseg.repository.RepositoryFileRepository;
import co.icesi.pdgseg.repository.RepositoryRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "cors.allowed-origins=http://localhost:5173"
        }
)
@AutoConfigureMockMvc
@Transactional
class RepositoryFilesControllerIntegrationTest extends PostgreSQLContainerBase {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired RepositoryRepository repositoryRepository;
    @Autowired RepositoryFileRepository repositoryFileRepository;
    @Autowired UserRepository userRepository;

    @TempDir
    Path tempDir;

    private String adminToken;
    private UUID repoId;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = obtainToken("admin", "admin123");
        repoId = createRepoWithFiles();
    }

    // ── Scenario 1: full inventory returned ──────────────────────────────────

    @Test
    void listFiles_readyRepo_returns200WithFiles() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/{id}/files", repoId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.inventoryStatus").value("READY_FOR_ANALYSIS"))
                .andExpect(jsonPath("$.totalFiles").value(3))
                .andExpect(jsonPath("$.files").isArray())
                .andExpect(jsonPath("$.files.length()").value(3));
    }

    // ── Scenario 2: 202 when inventory in progress ───────────────────────────

    @Test
    void listFiles_inventoryingRepo_returns202() throws Exception {
        Repository repo = repositoryRepository.findById(repoId).orElseThrow();
        repo.setInventoryStatus(InventoryStatus.INVENTORYING);
        repositoryRepository.save(repo);

        mockMvc.perform(get("/api/v1/repositories/{id}/files", repoId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.inventoryStatus").value("INVENTORYING"));
    }

    // ── Scenario 3: filter by language ───────────────────────────────────────

    @Test
    void listFiles_filterByLanguage_returnsOnlyMatchingFiles() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/{id}/files", repoId)
                        .param("language", "java")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files.length()").value(2));
    }

    // ── Scenario 4: filter by artifact type ──────────────────────────────────

    @Test
    void listFiles_filterByArtifactType_returnsOnlyMatchingFiles() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/{id}/files", repoId)
                        .param("artifactType", "DEPENDENCY_MANIFEST")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files.length()").value(1));
    }

    // ── Scenario 5: metadata fields present ──────────────────────────────────

    @Test
    void listFiles_eachFileHasRequiredMetadata() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/{id}/files", repoId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.files[0].path").exists())
                .andExpect(jsonPath("$.files[0].language").exists())
                .andExpect(jsonPath("$.files[0].artifactType").exists())
                .andExpect(jsonPath("$.files[0].sizeBytes").exists())
                .andExpect(jsonPath("$.files[0].sha256").exists());
    }

    // ── Scenario 6: 404 for unknown repo ─────────────────────────────────────

    @Test
    void listFiles_unknownRepo_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/{id}/files", UUID.randomUUID())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    // ── Scenario 7: unauthenticated request ──────────────────────────────────

    @Test
    void listFiles_noToken_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/{id}/files", repoId))
                .andExpect(status().isUnauthorized());
    }

    // ── Scenario 8: summary fields present ───────────────────────────────────

    @Test
    void listFiles_responseIncludesSummary() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/{id}/files", repoId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.byLanguage").exists())
                .andExpect(jsonPath("$.byArtifactType").exists())
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(1));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String obtainToken(String username, String password) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("username", username, "password", password));
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();
        Map<?, ?> resp = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        return (String) resp.get("accessToken");
    }

    private UUID createRepoWithFiles() {
        User admin = userRepository.findByUsername("admin").orElseThrow();

        Repository repo = new Repository();
        repo.setUserId(admin.getId());
        repo.setStatus(RepositoryStatus.READY_FOR_ANALYSIS);
        repo.setInventoryStatus(InventoryStatus.READY_FOR_ANALYSIS);
        repo.setSourceType("ZIP");
        repo.setOriginalName("test-repo.zip");
        repo.setPathInSandbox(tempDir.toString());
        repo.setCreatedAt(OffsetDateTime.now());
        repo.setExpiresAt(OffsetDateTime.now().plusHours(24));
        repo = repositoryRepository.save(repo);

        addFile(repo, "src/Main.java", "java", ArtifactType.SOURCE_CODE, 1024L, "abc123");
        addFile(repo, "src/Service.java", "java", ArtifactType.SOURCE_CODE, 2048L, "def456");
        addFile(repo, "pom.xml", "xml", ArtifactType.DEPENDENCY_MANIFEST, 512L, "ghi789");

        return repo.getId();
    }

    private void addFile(Repository repo, String path, String language,
                         ArtifactType type, long size, String sha) {
        RepositoryFile file = new RepositoryFile();
        file.setRepository(repo);
        file.setPath(path);
        file.setLanguage(language);
        file.setArtifactType(type);
        file.setSizeBytes(size);
        file.setSha256(sha);
        repositoryFileRepository.save(file);
    }
}
