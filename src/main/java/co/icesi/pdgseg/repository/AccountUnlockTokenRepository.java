package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.AccountUnlockToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

public interface AccountUnlockTokenRepository extends JpaRepository<AccountUnlockToken, UUID> {

    Optional<AccountUnlockToken> findByTokenHash(String tokenHash);

    /** Invalidates the pending links of a user, so only the one of the current lock works. */
    @Modifying
    @Query("UPDATE AccountUnlockToken t SET t.usedAt = :now WHERE t.user.id = :userId AND t.usedAt IS NULL")
    int invalidatePending(@Param("userId") UUID userId, @Param("now") OffsetDateTime now);

    @Modifying
    @Query("DELETE FROM AccountUnlockToken t WHERE t.expiresAt < :before OR t.usedAt < :before")
    int deleteFinishedBefore(@Param("before") OffsetDateTime before);
}
