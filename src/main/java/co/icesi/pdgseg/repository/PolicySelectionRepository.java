package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.PolicySelection;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PolicySelectionRepository extends JpaRepository<PolicySelection, UUID> {
    Optional<PolicySelection> findByRepositoryId(UUID repositoryId);
    boolean existsByRepositoryId(UUID repositoryId);
}
