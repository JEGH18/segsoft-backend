package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Finding;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface FindingRepository extends JpaRepository<Finding, UUID>, JpaSpecificationExecutor<Finding> {
    List<Finding> findByAnalysisId(UUID analysisId);
    long countByAnalysisIdAndPolicyId(UUID analysisId, UUID policyId);
    long countByAnalysisIdAndPolicyIdAndSeverityIn(UUID analysisId, UUID policyId, Collection<SeverityLevel> severities);
    void deleteByAnalysisId(UUID analysisId);
}
