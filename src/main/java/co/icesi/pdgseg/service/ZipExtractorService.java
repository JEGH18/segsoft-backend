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
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

@Service
public class ZipExtractorService {

    private static final Logger log = LoggerFactory.getLogger(ZipExtractorService.class);

    private static final int BUFFER_SIZE = 64 * 1024;

    @Value("${sandbox.max-repo-size-mb:100}")
    private long maxRepoSizeMb;

    @Value("${sandbox.max-file-count:5000}")
    private int maxFileCount;

    @Value("${sandbox.max-compression-ratio:100}")
    private long maxCompressionRatio;

    @Value("${sandbox.max-extracted-size-mb:500}")
    private long maxExtractedSizeMb = 500;

    private SandboxExclusions exclusions = SandboxExclusions.defaults();

    /**
     * fileCount: files written to the sandbox. excludedCount: entries skipped because they are
     * in an excluded directory (node_modules/, .git/, dist/...) or match an excluded file
     * pattern; they are not extracted and do not count against the file limit.
     */
    public record ExtractionResult(String sha256, int fileCount, int excludedCount) {}

    public ExtractionResult extract(MultipartFile file, Path targetDir) {
        validateContentType(file);
        validateSize(file);

        Path root = targetDir.toAbsolutePath().normalize();
        try {
            Files.createDirectories(root);
            ExtractionResult result = computeSha256AndExtract(file.getInputStream(), root, file.getSize());
            if (result.fileCount() == 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, result.excludedCount() > 0
                        ? "El ZIP solo contiene carpetas que no se analizan (node_modules, .git, dist, build...). "
                          + "Incluye el código fuente del proyecto."
                        : "El ZIP está vacío o no es un archivo ZIP válido.");
            }
            return result;
        } catch (ResponseStatusException e) {
            deleteQuietly(root);
            throw e;
        } catch (ZipException e) {
            deleteQuietly(root);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El archivo no es un ZIP válido o está dañado.");
        } catch (IOException e) {
            deleteQuietly(root);
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

    private ExtractionResult computeSha256AndExtract(InputStream inputStream, Path targetDir, long compressedSize)
            throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        int fileCount = 0;
        int excludedCount = 0;
        long maxExtractedBytes = maxExtractedSizeMb * 1024L * 1024L;
        // Both limits are checked while writing, every buffer: an entry that expands to
        // gigabytes is stopped before it fills the disk, not after.
        long ratioLimitBytes = Math.max(compressedSize, 1L) * maxCompressionRatio;
        long[] bytesExtracted = {0};
        long skippedBytes = 0;
        byte[] buffer = new byte[BUFFER_SIZE];

        try (DigestInputStream dis = new DigestInputStream(inputStream, digest);
             ZipInputStream zis = new ZipInputStream(dis)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // ZIPs made on Windows may use '\' as separator.
                String entryName = entry.getName().replace('\\', '/');

                Path destPath = targetDir.resolve(entryName).normalize();
                if (!destPath.startsWith(targetDir)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                            "Ruta maliciosa detectada (path traversal): " + entryName);
                }

                if (exclusions.isExcluded(entryName)) {
                    if (!entry.isDirectory()) {
                        excludedCount++;
                    }
                    // Skipping still inflates the entry: it counts against the compression
                    // ratio (not against the disk limit), so a bomb hidden in node_modules/
                    // cannot keep the CPU busy either.
                    int read;
                    while ((read = zis.read(buffer)) != -1) {
                        skippedBytes += read;
                        if (bytesExtracted[0] + skippedBytes > ratioLimitBytes) {
                            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                                    "ZIP bomb detectada: ratio de compresión supera " + maxCompressionRatio + ":1");
                        }
                    }
                    zis.closeEntry();
                    continue;
                }

                if (entry.isDirectory() || entryName.endsWith("/")) {
                    Files.createDirectories(destPath);
                } else {
                    fileCount++;
                    if (fileCount > maxFileCount) {
                        throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                                "El ZIP supera el límite de " + maxFileCount + " archivos (sin contar node_modules, "
                                + ".git, dist, build y otras carpetas que no se analizan).");
                    }
                    Files.createDirectories(destPath.getParent());
                    try (OutputStream out = Files.newOutputStream(destPath)) {
                        int read;
                        while ((read = zis.read(buffer)) != -1) {
                            bytesExtracted[0] += read;
                            if (bytesExtracted[0] + skippedBytes > ratioLimitBytes) {
                                throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                                        "ZIP bomb detectada: ratio de compresión supera " + maxCompressionRatio + ":1");
                            }
                            if (bytesExtracted[0] > maxExtractedBytes) {
                                throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                                        "El contenido descomprimido supera el límite de " + maxExtractedSizeMb + " MB");
                            }
                            out.write(buffer, 0, read);
                        }
                    }
                }
                zis.closeEntry();
            }
            // Read what is left (central directory), so the hash covers the whole upload.
            while (dis.read(buffer) != -1) {
                // drain
            }
        }
        if (excludedCount > 0) {
            log.info("ZIP: {} archivos extraídos, {} omitidos por estar en carpetas excluidas", fileCount, excludedCount);
        }
        return new ExtractionResult(HexFormat.of().formatHex(digest.digest()), fileCount, excludedCount);
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
