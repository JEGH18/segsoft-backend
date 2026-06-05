package co.icesi.pdgseg.scheduler;

import co.icesi.pdgseg.service.RepositoryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class RepositoryCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(RepositoryCleanupJob.class);

    private final RepositoryService repositoryService;

    public RepositoryCleanupJob(RepositoryService repositoryService) {
        this.repositoryService = repositoryService;
    }

    // Runs every hour
    @Scheduled(cron = "0 0 * * * *")
    public void cleanupExpiredRepositories() {
        log.info("Iniciando limpieza de repositorios expirados");
        try {
            repositoryService.expireOldRepositories();
        } catch (Exception e) {
            log.error("Error durante limpieza de repositorios expirados", e);
        }
    }
}
