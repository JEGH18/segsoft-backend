package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Report;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface ReportRepository extends JpaRepository<Report, UUID> {

    Page<Report> findAllByOrderByGeneratedAtDesc(Pageable pageable);

    Page<Report> findByAnalysisIdOrderByGeneratedAtDesc(UUID analysisId, Pageable pageable);
}
