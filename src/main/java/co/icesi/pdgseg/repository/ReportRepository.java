package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Report;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.UUID;

public interface ReportRepository extends JpaRepository<Report, UUID> {

    Page<Report> findAllByOrderByGeneratedAtDesc(Pageable pageable);

    Page<Report> findByAnalysisIdOrderByGeneratedAtDesc(UUID analysisId, Pageable pageable);

    /**
     * Reads the repository id from the frozen content rather than joining
     * analyses, so the history survives the analysis/repository being deleted
     * (analysis_id is set to NULL then). Backed by idx_reports_repository_id.
     */
    @Query(value = "SELECT * FROM reports WHERE content -> 'metadata' ->> 'repositoryId' = :repositoryId "
            + "ORDER BY generated_at DESC",
            countQuery = "SELECT count(*) FROM reports WHERE content -> 'metadata' ->> 'repositoryId' = :repositoryId",
            nativeQuery = true)
    Page<Report> findByRepositoryId(@Param("repositoryId") String repositoryId, Pageable pageable);
}
