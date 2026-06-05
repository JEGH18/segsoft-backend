package co.icesi.pdgseg.integration;

import co.icesi.pdgseg.dto.response.RepositoryResponse;
import co.icesi.pdgseg.entity.Role;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.entity.enums.RepositoryStatus;
import co.icesi.pdgseg.entity.enums.RoleType;
import co.icesi.pdgseg.entity.enums.SourceType;
import co.icesi.pdgseg.repository.RoleRepository;
import co.icesi.pdgseg.repository.UserRepository;
import co.icesi.pdgseg.service.RepositoryService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jwt.secret=integration-test-secret-minimum-32-characters-ok",
                "jwt.access-token-expiration-ms=900000",
                "jwt.refresh-token-expiration-ms=28800000",
                "sandbox.root=/tmp/pdgseg-repo-integration-test",
                "cors.allowed-origins=http://localhost:5173"
        }
)
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RepositoryControllerIntegrationTest extends PostgreSQLContainerBase {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private RepositoryService repositoryService;

    private String devToken;

    private final UUID repoId = UUID.randomUUID();

    private final RepositoryResponse mockZipRepo = new RepositoryResponse(
            UUID.randomUUID(), RepositoryStatus.READY_FOR_ANALYSIS, SourceType.ZIP,
            "test.zip", null, null, 5, null,
            OffsetDateTime.now(), OffsetDateTime.now().plusHours(24)
    );

    private final RepositoryResponse mockGitRepo = new RepositoryResponse(
            UUID.randomUUID(), RepositoryStatus.READY_FOR_ANALYSIS, SourceType.GIT,
            "repo", "https://github.com/user/repo.git", "main", 12, null,
            OffsetDateTime.now(), OffsetDateTime.now().plusHours(24)
    );

    @BeforeAll
    void seedUserAndLogin() throws Exception {
        Role devRole = roleRepository.findByName(RoleType.DEVELOPER.name())
                .orElseGet(() -> roleRepository.save(newRole(RoleType.DEVELOPER)));

        User dev = userRepository.findByUsername("dev_test")
                .orElse(new User());
        dev.setUsername("dev_test");
        dev.setPasswordHash(passwordEncoder.encode("dev_pass123!"));
        dev.setEnabled(true);
        dev.setFailedAttempts(0);
        dev.setRoles(Set.of(devRole));
        userRepository.saveAndFlush(dev);

        String loginBody = objectMapper.writeValueAsString(
                Map.of("username", "dev_test", "password", "dev_pass123!"));

        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody))
                .andExpect(status().isOk())
                .andReturn();

        Map<?, ?> resp = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        devToken = (String) resp.get("accessToken");
    }

    // --- POST /api/v1/repositories (ZIP) ---

    @Test
    void uploadZip_withoutAuth_returns401() throws Exception {
        mockMvc.perform(multipart("/api/v1/repositories")
                        .file(smallZip()))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(repositoryService);
    }

    @Test
    void uploadZip_withAuthAndValidFile_returns201WithRepositoryId() throws Exception {
        when(repositoryService.uploadZip(any(), any())).thenReturn(mockZipRepo);

        mockMvc.perform(multipart("/api/v1/repositories")
                        .file(smallZip())
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("READY_FOR_ANALYSIS"))
                .andExpect(jsonPath("$.sourceType").value("ZIP"))
                .andExpect(jsonPath("$.fileCount").value(5));

        verify(repositoryService).uploadZip(any(), eq("dev_test"));
    }

    @Test
    void uploadZip_withoutFile_returns400() throws Exception {
        mockMvc.perform(multipart("/api/v1/repositories")
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(repositoryService);
    }

    @Test
    void uploadZip_serviceThrowsBadRequest_returns400() throws Exception {
        when(repositoryService.uploadZip(any(), any()))
                .thenThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "ZIP bomb detectada"));

        mockMvc.perform(multipart("/api/v1/repositories")
                        .file(smallZip())
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("ZIP bomb detectada"));
    }

    // --- POST /api/v1/repositories/git ---

    @Test
    void cloneGit_withoutAuth_returns401() throws Exception {
        String body = objectMapper.writeValueAsString(
                Map.of("gitUrl", "https://github.com/user/repo.git", "branch", "main"));

        mockMvc.perform(post("/api/v1/repositories/git")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(repositoryService);
    }

    @Test
    void cloneGit_withAuthAndValidRequest_returns201() throws Exception {
        when(repositoryService.cloneGit(any(), any(), any())).thenReturn(mockGitRepo);

        String body = objectMapper.writeValueAsString(
                Map.of("gitUrl", "https://github.com/user/repo.git", "branch", "main"));

        mockMvc.perform(post("/api/v1/repositories/git")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("READY_FOR_ANALYSIS"))
                .andExpect(jsonPath("$.sourceType").value("GIT"))
                .andExpect(jsonPath("$.gitUrl").value("https://github.com/user/repo.git"));

        verify(repositoryService).cloneGit(
                eq("https://github.com/user/repo.git"), eq("main"), eq("dev_test"));
    }

    @Test
    void cloneGit_withBlankUrl_returns400() throws Exception {
        String body = objectMapper.writeValueAsString(Map.of("gitUrl", ""));

        mockMvc.perform(post("/api/v1/repositories/git")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(repositoryService);
    }

    @Test
    void cloneGit_withNonHttpsUrl_returns400() throws Exception {
        String body = objectMapper.writeValueAsString(
                Map.of("gitUrl", "git@github.com:user/repo.git"));

        mockMvc.perform(post("/api/v1/repositories/git")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(repositoryService);
    }

    // --- GET /api/v1/repositories/{id} ---

    @Test
    void getRepository_withoutAuth_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/repositories/" + repoId))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getRepository_withAuth_returns200() throws Exception {
        when(repositoryService.findById(any(), any())).thenReturn(mockZipRepo);

        mockMvc.perform(get("/api/v1/repositories/" + repoId)
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY_FOR_ANALYSIS"));
    }

    @Test
    void getRepository_notFound_returns404() throws Exception {
        when(repositoryService.findById(any(), any()))
                .thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Repositorio no encontrado"));

        mockMvc.perform(get("/api/v1/repositories/" + repoId)
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isNotFound());
    }

    // --- DELETE /api/v1/repositories/{id} ---

    @Test
    void deleteRepository_withoutAuth_returns401() throws Exception {
        mockMvc.perform(delete("/api/v1/repositories/" + repoId))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deleteRepository_withAuth_returns204() throws Exception {
        doNothing().when(repositoryService).delete(any(), any());

        mockMvc.perform(delete("/api/v1/repositories/" + repoId)
                        .header("Authorization", "Bearer " + devToken))
                .andExpect(status().isNoContent());

        verify(repositoryService).delete(eq(repoId), eq("dev_test"));
    }

    // --- helpers ---

    private MockMultipartFile smallZip() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("Main.java"));
            zos.write("public class Main {}".getBytes());
            zos.closeEntry();
        }
        return new MockMultipartFile("file", "test.zip", "application/zip", baos.toByteArray());
    }

    private Role newRole(RoleType type) {
        Role r = new Role();
        r.setName(type.name());
        return r;
    }
}
