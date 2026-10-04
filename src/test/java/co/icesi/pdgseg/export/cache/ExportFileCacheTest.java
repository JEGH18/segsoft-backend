package co.icesi.pdgseg.export.cache;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExportFileCacheTest {

    private static final UUID REPORT = UUID.fromString("0f8f7c1e-4c1a-4f3e-9d7a-2b6c1d0e9a11");
    private static final String CHECKSUM = "9f2c4e1b7a3d5f60c8e9b1a2d3c4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6";

    @TempDir Path directory;
    private ExportFileCache cache;
    private final AtomicInteger generations = new AtomicInteger();

    @BeforeEach
    void setUp() {
        cache = new ExportFileCache(directory, Duration.ofHours(1), Clock.systemUTC());
    }

    private byte[] generate() {
        generations.incrementAndGet();
        return ("pdf-" + generations.get()).getBytes();
    }

    // ---- Key --------------------------------------------------------------------------

    @Test
    void keyIsReportFormatAndChecksum() {
        assertThat(ExportFileCache.key(REPORT, "PDF", CHECKSUM.toUpperCase()))
                .isEqualTo(REPORT + "_pdf_" + CHECKSUM);
    }

    @Test
    void keyCannotCarryAPath() {
        assertThatThrownBy(() -> ExportFileCache.key(REPORT, "../pdf", CHECKSUM))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ExportFileCache.key(REPORT, "pdf", "../../etc/passwd"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> cache.getOrCreate("../x", this::generate))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ---- MISS / HIT -------------------------------------------------------------------

    @Test
    void firstRequestIsAMissThatStoresTheFileAndTheNextOneAHit() {
        String key = ExportFileCache.key(REPORT, "pdf", CHECKSUM);

        ExportFileCache.Lookup first = cache.getOrCreate(key, this::generate);
        ExportFileCache.Lookup second = cache.getOrCreate(key, this::generate);

        assertThat(first.hit()).isFalse();
        assertThat(second.hit()).isTrue();
        assertThat(second.content()).isEqualTo(first.content());
        assertThat(generations).hasValue(1);
        assertThat(cache.pathFor(key)).exists();
    }

    @Test
    void aChangedChecksumIsADifferentEntry() {
        cache.getOrCreate(ExportFileCache.key(REPORT, "pdf", CHECKSUM), this::generate);
        String changed = "0".repeat(64);

        ExportFileCache.Lookup lookup = cache.getOrCreate(ExportFileCache.key(REPORT, "pdf", changed), this::generate);

        assertThat(lookup.hit()).isFalse();
        assertThat(generations).hasValue(2);
    }

    @Test
    void formatsAreCachedSeparately() {
        cache.getOrCreate(ExportFileCache.key(REPORT, "pdf", CHECKSUM), this::generate);
        assertThat(cache.getOrCreate(ExportFileCache.key(REPORT, "sarif", CHECKSUM), this::generate).hit()).isFalse();
    }

    @Test
    void aFailedGenerationCachesNothing() {
        String key = ExportFileCache.key(REPORT, "pdf", CHECKSUM);

        assertThatThrownBy(() -> cache.getOrCreate(key, () -> {
            throw new IllegalStateException("render failed");
        })).hasMessage("render failed");

        assertThat(cache.pathFor(key)).doesNotExist();
        assertThat(cache.getOrCreate(key, this::generate).hit()).isFalse();
    }

    // ---- TTL --------------------------------------------------------------------------

    @Test
    void anExpiredEntryIsRegenerated() throws IOException {
        String key = ExportFileCache.key(REPORT, "pdf", CHECKSUM);
        cache.getOrCreate(key, this::generate);
        age(cache.pathFor(key), Duration.ofMinutes(61));

        ExportFileCache.Lookup lookup = cache.getOrCreate(key, this::generate);

        assertThat(lookup.hit()).isFalse();
        assertThat(new String(lookup.content())).isEqualTo("pdf-2");
    }

    @Test
    void anEntryWithinTheTtlIsServed() throws IOException {
        String key = ExportFileCache.key(REPORT, "pdf", CHECKSUM);
        cache.getOrCreate(key, this::generate);
        age(cache.pathFor(key), Duration.ofMinutes(59));

        assertThat(cache.getOrCreate(key, this::generate).hit()).isTrue();
    }

    @Test
    void ttlIsMeasuredWithTheConfiguredClock() {
        String key = ExportFileCache.key(REPORT, "pdf", CHECKSUM);
        cache.getOrCreate(key, this::generate);
        ExportFileCache twoHoursLater = new ExportFileCache(directory, Duration.ofHours(1),
                Clock.fixed(Instant.now().plus(Duration.ofHours(2)), java.time.ZoneOffset.UTC));

        assertThat(twoHoursLater.getOrCreate(key, this::generate).hit()).isFalse();
    }

    @Test
    void zeroTtlDisablesTheCache() {
        ExportFileCache disabled = new ExportFileCache(directory, Duration.ZERO, Clock.systemUTC());
        String key = ExportFileCache.key(REPORT, "pdf", CHECKSUM);

        disabled.getOrCreate(key, this::generate);
        assertThat(disabled.getOrCreate(key, this::generate).hit()).isFalse();
        assertThat(disabled.isEnabled()).isFalse();
        assertThat(disabled.pathFor(key)).doesNotExist();
    }

    @Test
    void negativeTtlIsRejected() {
        assertThatThrownBy(() -> new ExportFileCache(directory, Duration.ofMinutes(-1), Clock.systemUTC()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ---- Cleanup ----------------------------------------------------------------------

    @Test
    void evictExpiredRemovesOnlyExpiredExportsAndAbandonedTempFiles() throws IOException {
        String fresh = ExportFileCache.key(REPORT, "pdf", CHECKSUM);
        String stale = ExportFileCache.key(REPORT, "sarif", CHECKSUM);
        cache.getOrCreate(fresh, this::generate);
        cache.getOrCreate(stale, this::generate);
        age(cache.pathFor(stale), Duration.ofHours(2));
        Path abandonedTemp = Files.writeString(directory.resolve("abandoned.tmp"), "partial");
        age(abandonedTemp, Duration.ofHours(2));
        Path unrelated = Files.writeString(directory.resolve("notes.txt"), "keep");
        age(unrelated, Duration.ofHours(2));

        assertThat(cache.evictExpired()).isEqualTo(2);
        assertThat(cache.pathFor(fresh)).exists();
        assertThat(cache.pathFor(stale)).doesNotExist();
        assertThat(abandonedTemp).doesNotExist();
        assertThat(unrelated).exists();
    }

    @Test
    void cleanupJobDelegatesToTheCache() throws IOException {
        String stale = ExportFileCache.key(REPORT, "pdf", CHECKSUM);
        cache.getOrCreate(stale, this::generate);
        age(cache.pathFor(stale), Duration.ofHours(2));

        new ExportCacheCleanupJob(cache).evictExpiredExports();

        assertThat(cache.pathFor(stale)).doesNotExist();
    }

    @Test
    void evictingAMissingDirectoryIsANoOp() {
        ExportFileCache missing = new ExportFileCache(directory.resolve("nope"), Duration.ofHours(1), Clock.systemUTC());
        assertThat(missing.evictExpired()).isZero();
    }

    @Test
    void startupClearsFilesLeftByAPreviousDeployment() {
        cache.getOrCreate(ExportFileCache.key(REPORT, "pdf", CHECKSUM), this::generate);
        assertThat(cache.clear()).isEqualTo(1);
        assertThat(directory).isEmptyDirectory();
    }

    // ---- Concurrency ------------------------------------------------------------------

    @Test
    void concurrentRequestsForTheSameKeyGenerateTheFileOnce() throws Exception {
        String key = ExportFileCache.key(REPORT, "pdf", CHECKSUM);
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<ExportFileCache.Lookup>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Callable<ExportFileCache.Lookup> task = () -> {
                    start.await();
                    return cache.getOrCreate(key, () -> {
                        sleep(100);
                        return generate();
                    });
                };
                results.add(pool.submit(task));
            }
            start.countDown();
            int misses = 0;
            for (Future<ExportFileCache.Lookup> result : results) {
                if (!result.get(10, TimeUnit.SECONDS).hit()) {
                    misses++;
                }
            }
            assertThat(generations).hasValue(1);
            assertThat(misses).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    private static void age(Path file, Duration age) throws IOException {
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().minus(age)));
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
