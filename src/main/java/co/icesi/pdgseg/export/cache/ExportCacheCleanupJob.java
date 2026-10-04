package co.icesi.pdgseg.export.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Periodically removes expired exports from {@link ExportFileCache}. */
@Component
public class ExportCacheCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(ExportCacheCleanupJob.class);

    private final ExportFileCache cache;

    public ExportCacheCleanupJob(ExportFileCache cache) {
        this.cache = cache;
    }

    @Scheduled(fixedDelayString = "${report.export.cache.cleanup-interval}",
            initialDelayString = "${report.export.cache.cleanup-interval}")
    public void evictExpiredExports() {
        try {
            int removed = cache.evictExpired();
            if (removed > 0) {
                log.info("Caché de exportaciones: {} archivos expirados eliminados", removed);
            }
        } catch (Exception e) {
            log.error("Error limpiando la caché de exportaciones", e);
        }
    }
}
