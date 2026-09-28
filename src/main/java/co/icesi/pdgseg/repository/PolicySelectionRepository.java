package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.PolicySelection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PolicySelectionRepository extends JpaRepository<PolicySelection, UUID> {
    Optional<PolicySelection> findByRepositoryId(UUID repositoryId);
    boolean existsByRepositoryId(UUID repositoryId);

    @Query("SELECT ps.repository.id FROM PolicySelection ps WHERE ps.policySet.id = :policySetId")
    List<UUID> findRepositoryIdsByPolicySetId(@Param("policySetId") UUID policySetId);
}
