package co.icesi.pdgseg.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Service
public class ZipExtractorService {

    private static final Logger log = LoggerFactory.getLogger(ZipExtractorService.class);

    @Value("${sandbox.max-repo-size-mb:100}")
    private long maxRepoSizeMb;

    @Value("${sandbox.max-file-count:5000}")
    private int maxFileCount;

    @Value("${sandbox.max-compression-ratio:100}")
    private long maxCompressionRatio;

    public record ExtractionResult(String sha256, int fileCount) {}

    public ExtractionResult extract(MultipartFile file, Path targetDir) {
        validateContentType(file);
        validateSize(file);

        try {
            Files.createDirectories(targetDir);
            String sha256 = computeSha256AndExtract(file.getInputStream(), targetDir, file.getSize());
            int count = countExtractedFiles(targetDir);
            return new ExtractionResult(sha256, count);
        } catch (ResponseStatusException e) {
            deleteQuietly(targetDir);
            throw e;
        } catch (IOException e) {
            deleteQuietly(targetDir);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al descomprimir el archivo");
        }
    }

    private void validateContentType(MultipartFile file) {
        String ct = file.getContentType();
        if (ct == null || (!ct.contains("zip") && !ct.equals("application/octet-stream"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Solo se aceptan archivos ZIP. Tipo recibido: " + ct);
        }
    }

    private void validateSize(MultipartFile file) {
        long maxBytes = maxRepoSizeMb * 1024L * 1024L;
        if (file.getSize() > maxBytes) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                    "El archivo supera el límite de " + maxRepoSizeMb + " MB");
        }
    }

    private String computeSha256AndExtract(InputStream inputStream, Path targetDir, long compressedSize) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        int fileCount = 0;
        long bytesExtracted = 0;

        try (DigestInputStream dis = new DigestInputStream(inputStream, digest);
             ZipInputStream zis = new ZipInputStream(dis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();

                Path destPath = targetDir.resolve(entryName).normalize();
                if (!destPath.startsWith(targetDir)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                            "Ruta maliciosa detectada (path traversal): " + entryName);
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(destPath);
                } else {
                    fileCount++;
                    if (fileCount > maxFileCount) {
                        throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                                "El ZIP supera el límite de " + maxFileCount + " archivos");
                    }
                    Files.createDirectories(destPath.getParent());
                    long written = Files.copy(zis, destPath, StandardCopyOption.REPLACE_EXISTING);
                    bytesExtracted += written;

                    if (compressedSize > 0 && bytesExtracted / Math.max(compressedSize, 1L) > maxCompressionRatio) {
                        throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                                "ZIP bomb detectada: ratio de compresión supera " + maxCompressionRatio + ":1");
                    }
                }
                zis.closeEntry();
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private int countExtractedFiles(Path dir) throws IOException {
        try (var stream = Files.walk(dir)) {
            return (int) stream.filter(Files::isRegularFile).count();
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
