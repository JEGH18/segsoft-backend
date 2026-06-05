package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Analysis;
import co.icesi.pdgseg.entity.enums.AnalysisStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface AnalysisRepository extends JpaRepository<Analysis, UUID> {
    boolean existsByRepositoryIdAndStatusIn(UUID repositoryId, Collection<AnalysisStatus> statuses);
    List<Analysis> findByRepositoryId(UUID repositoryId);
}
