package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.AnalysisSnapshot;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AnalysisSnapshotRepository extends JpaRepository<AnalysisSnapshot, UUID> {
    Optional<AnalysisSnapshot> findByAnalysisId(UUID analysisId);
}
