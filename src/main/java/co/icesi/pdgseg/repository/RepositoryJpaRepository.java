package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.enums.RepositoryStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RepositoryJpaRepository extends JpaRepository<Repository, UUID> {

    Optional<Repository> findByIdAndUserUsername(UUID id, String username);

    @Query("SELECT r FROM Repository r WHERE r.expiresAt < :now AND r.status NOT IN ('EXPIRED','ARCHIVED')")
    List<Repository> findExpired(OffsetDateTime now);
}
