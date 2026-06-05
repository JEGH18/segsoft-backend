package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.PolicyResult;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface PolicyResultRepository extends JpaRepository<PolicyResult, UUID> {
    List<PolicyResult> findByAnalysisId(UUID analysisId);
    void deleteByAnalysisId(UUID analysisId);
}
