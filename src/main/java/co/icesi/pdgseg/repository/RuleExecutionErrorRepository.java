package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.RuleExecutionError;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface RuleExecutionErrorRepository extends JpaRepository<RuleExecutionError, UUID> {
    List<RuleExecutionError> findByAnalysisId(UUID analysisId);
    void deleteByAnalysisId(UUID analysisId);
}
