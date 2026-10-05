package co.icesi.pdgseg.export.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Filesystem cache of exported report files (PDF, SARIF...), keyed by
 * {reportId}_{format}_{checksum}: a report whose content changes gets a new
 * checksum and therefore a new key, so a stale export is never served for it.
 *
 * Entries expire a fixed TTL after they were generated (reading them does not
 * extend it). Expired files are dropped on read and swept periodically by
 * {@link ExportCacheCleanupJob}. The cache is an optimization only: any I/O
 * problem is logged and treated as a miss, never as a failed download.
 */
@Component
public class ExportFileCache {

    private static final Logger log = LoggerFactory.getLogger(ExportFileCache.class);

    /** Also guarantees the key cannot carry path separators or "..". */
    private static final Pattern KEY = Pattern.compile("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}_[a-z0-9]{1,16}_[0-9a-f]{64}");
    private static final String SUFFIX = ".export";
    private static final String TEMP_SUFFIX = ".tmp";

    public record Lookup(byte[] content, boolean hit) {
    }

    private final Path directory;
    private final Duration ttl;
    private final Clock clock;
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    @Autowired
    public ExportFileCache(
            @Value("${report.export.cache.dir}") String directory,
            @Value("${report.export.cache.ttl}") Duration ttl
    ) {
        this(Paths.get(directory), ttl, Clock.systemUTC());
    }

    ExportFileCache(Path directory, Duration ttl, Clock clock) {
        if (ttl.isNegative()) {
            throw new IllegalArgumentException("report.export.cache.ttl no puede ser negativo: " + ttl);
        }
        this.directory = directory.toAbsolutePath().normalize();
        this.ttl = ttl;
        this.clock = clock;
    }

    public static String key(UUID reportId, String format, String checksum) {
        String key = reportId + "_" + format.toLowerCase(Locale.ROOT) + "_" + checksum.toLowerCase(Locale.ROOT);
        if (!KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("Clave de caché inválida: " + key);
        }
        return key;
    }

    public boolean isEnabled() {
        return !ttl.isZero();
    }

    public Duration ttl() {
        return ttl;
    }

    /**
     * Returns the cached file for {@code key} (a hit) or generates it with
     * {@code generator}, stores it and returns it (a miss). Concurrent
     * requests for the same key wait for a single generation instead of
     * rendering the same file several times. If the generator throws, nothing
     * is cached and the exception propagates.
     */
    public Lookup getOrCreate(String key, Supplier<byte[]> generator) {
        requireValidKey(key);
        if (!isEnabled()) {
            return new Lookup(generator.get(), false);
        }
        Optional<byte[]> cached = read(key);
        if (cached.isPresent()) {
            return new Lookup(cached.get(), true);
        }
        Object lock = locks.computeIfAbsent(key, k -> new Object());
        try {
            synchronized (lock) {
                cached = read(key);
                if (cached.isPresent()) {
                    return new Lookup(cached.get(), true);
                }
                byte[] content = generator.get();
                write(key, content);
                return new Lookup(content, false);
            }
        } finally {
            locks.remove(key, lock);
        }
    }

    /** Deletes expired entries and abandoned temporary files; returns how many were removed. */
    public int evictExpired() {
        if (!Files.isDirectory(directory)) {
            return 0;
        }
        int removed = 0;
        try (DirectoryStream<Path> files = Files.newDirectoryStream(directory)) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                if ((name.endsWith(SUFFIX) || name.endsWith(TEMP_SUFFIX)) && isExpired(file) && deleteQuietly(file)) {
                    removed++;
                }
            }
        } catch (IOException e) {
            log.warn("No se pudo recorrer la caché de exportaciones {}", directory, e);
        }
        return removed;
    }

    /**
     * Exports are rendered by the code of the running version, so files left
     * by a previous deployment (possibly with another template or masking
     * rules) are discarded at startup instead of being served until they
     * expire.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void clearOnStartup() {
        int removed = clear();
        if (removed > 0) {
            log.info("Caché de exportaciones vaciada al iniciar: {} archivos eliminados", removed);
        }
    }

    int clear() {
        if (!Files.isDirectory(directory)) {
            return 0;
        }
        int removed = 0;
        try (DirectoryStream<Path> files = Files.newDirectoryStream(directory)) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                if ((name.endsWith(SUFFIX) || name.endsWith(TEMP_SUFFIX)) && deleteQuietly(file)) {
                    removed++;
                }
            }
        } catch (IOException e) {
            log.warn("No se pudo vaciar la caché de exportaciones {}", directory, e);
        }
        return removed;
    }

    Path pathFor(String key) {
        return directory.resolve(key + SUFFIX);
    }

    // ---- internals ------------------------------------------------------------------

    private Optional<byte[]> read(String key) {
        Path file = pathFor(key);
        try {
            if (isExpired(file)) {
                deleteQuietly(file);
                return Optional.empty();
            }
            return Optional.of(Files.readAllBytes(file));
        } catch (NoSuchFileException e) {
            return Optional.empty();
        } catch (IOException | UncheckedIOException e) {
            log.warn("No se pudo leer la exportación cacheada {}; se regenera", file, e);
            return Optional.empty();
        }
    }

    private void write(String key, byte[] content) {
        Path temp = null;
        try {
            Files.createDirectories(directory);
            temp = Files.createTempFile(directory, key, TEMP_SUFFIX);
            Files.write(temp, content);
            Files.move(temp, pathFor(key), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            log.warn("No se pudo guardar la exportación en caché ({}); se sirve sin cachear", key, e);
            if (temp != null) {
                deleteQuietly(temp);
            }
        }
    }

    private boolean isExpired(Path file) throws IOException {
        Instant generatedAt = Files.getLastModifiedTime(file).toInstant();
        return !generatedAt.plus(ttl).isAfter(clock.instant());
    }

    private static boolean deleteQuietly(Path file) {
        try {
            return Files.deleteIfExists(file);
        } catch (IOException e) {
            log.warn("No se pudo eliminar {} de la caché de exportaciones", file, e);
            return false;
        }
    }

    private static void requireValidKey(String key) {
        if (key == null || !KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("Clave de caché inválida: " + key);
        }
    }
}
