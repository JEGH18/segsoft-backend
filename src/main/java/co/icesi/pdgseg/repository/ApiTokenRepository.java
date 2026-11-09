package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.ApiToken;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApiTokenRepository extends JpaRepository<ApiToken, UUID> {

    /** With the owner and its roles, which authentication needs. */
    @EntityGraph(attributePaths = {"createdBy", "createdBy.roles"})
    Optional<ApiToken> findByTokenHash(String tokenHash);

    @EntityGraph(attributePaths = "createdBy")
    List<ApiToken> findAllByOrderByCreatedAtDesc();

    @EntityGraph(attributePaths = "createdBy")
    List<ApiToken> findAllByCreatedByUsernameOrderByCreatedAtDesc(String username);

    long countByCreatedByUsernameAndExpiresAtAfter(String username, OffsetDateTime now);

    @Modifying
    @Query("UPDATE ApiToken t SET t.lastUsedAt = :now WHERE t.id = :id")
    void markUsed(@Param("id") UUID id, @Param("now") OffsetDateTime now);
}
