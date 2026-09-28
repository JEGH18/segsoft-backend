package co.icesi.pdgseg.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ZipExtractorServiceTest {

    private ZipExtractorService service;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        service = new ZipExtractorService();
        ReflectionTestUtils.setField(service, "maxRepoSizeMb", 10L);
        ReflectionTestUtils.setField(service, "maxFileCount", 100);
        ReflectionTestUtils.setField(service, "maxCompressionRatio", 100L);
    }

    @Test
    void extract_validZip_returnsResultWithFileCountAndSha256() throws IOException {
        byte[] zipBytes = buildZip(3, 100);
        MockMultipartFile file = multipartZip("repo.zip", zipBytes);
        Path dest = tempDir.resolve("out");

        ZipExtractorService.ExtractionResult result = service.extract(file, dest);

        assertThat(result.fileCount()).isEqualTo(3);
        assertThat(result.sha256()).hasSize(64); // SHA-256 hex is always 64 chars
        assertThat(Files.list(dest).count()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void extract_fileTooLarge_throwsPayloadTooLarge() {
        byte[] oversized = new byte[11 * 1024 * 1024]; // 11 MB > limit of 10 MB
        MockMultipartFile file = multipartZip("big.zip", oversized);
        Path dest = tempDir.resolve("out-size");

        assertThatThrownBy(() -> service.extract(file, dest))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE.value()));
    }

    @Test
    void extract_tooManyFiles_throwsPayloadTooLarge() throws IOException {
        byte[] zipBytes = buildZip(101, 10); // 101 files > limit of 100
        MockMultipartFile file = multipartZip("many.zip", zipBytes);
        Path dest = tempDir.resolve("out-count");

        assertThatThrownBy(() -> service.extract(file, dest))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE.value()));
    }

    @Test
    void extract_pathTraversalEntry_throwsBadRequest() throws IOException {
        byte[] zipBytes = buildZipWithEntry("../../../etc/passwd", "malicious");
        MockMultipartFile file = multipartZip("traversal.zip", zipBytes);
        Path dest = tempDir.resolve("out-traversal");

        assertThatThrownBy(() -> service.extract(file, dest))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(HttpStatus.BAD_REQUEST.value()));
    }

    @Test
    void extract_zipBombAboveRatioLimit_throwsPayloadTooLarge() throws IOException {
        // 5 MB of zeros compress to ~5 KB → ratio ≈ 1000 >> 100
        byte[] zeros = new byte[5 * 1024 * 1024];
        byte[] zipBytes = buildZipWithEntry("zeros.bin", zeros);
        MockMultipartFile file = multipartZip("bomb.zip", zipBytes);
        Path dest = tempDir.resolve("out-bomb");

        assertThatThrownBy(() -> service.extract(file, dest))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE.value()));
    }

    @Test
    void extract_wrongContentType_throwsBadRequest() throws IOException {
        byte[] zipBytes = buildZip(1, 10);
        MockMultipartFile file = new MockMultipartFile("file", "file.zip", "text/plain", zipBytes);
        Path dest = tempDir.resolve("out-ct");

        assertThatThrownBy(() -> service.extract(file, dest))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode().value())
                        .isEqualTo(HttpStatus.BAD_REQUEST.value()));
    }

    @Test
    void extract_zipWithDirectory_skipsDirectoryEntries() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("src/"));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("src/Main.java"));
            zos.write("public class Main {}".getBytes());
            zos.closeEntry();
        }
        MockMultipartFile file = multipartZip("dir.zip", baos.toByteArray());
        Path dest = tempDir.resolve("out-dir");

        ZipExtractorService.ExtractionResult result = service.extract(file, dest);

        assertThat(result.fileCount()).isEqualTo(1);
    }

    // --- helpers ---

    private byte[] buildZip(int fileCount, int fileSize) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            byte[] content = new byte[fileSize];
            for (int i = 0; i < fileCount; i++) {
                zos.putNextEntry(new ZipEntry("file" + i + ".txt"));
                zos.write(content);
                zos.closeEntry();
            }
        }
        return baos.toByteArray();
    }

    private byte[] buildZipWithEntry(String entryName, byte[] content) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry(entryName));
            zos.write(content);
            zos.closeEntry();
        }
        return baos.toByteArray();
    }

    private byte[] buildZipWithEntry(String entryName, String content) throws IOException {
        return buildZipWithEntry(entryName, content.getBytes());
    }

    private MockMultipartFile multipartZip(String filename, byte[] content) {
        return new MockMultipartFile("file", filename, "application/zip", content);
    }
}
