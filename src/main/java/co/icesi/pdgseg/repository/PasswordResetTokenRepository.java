package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.PasswordResetToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    /**
     * Locks the row (SELECT ... FOR UPDATE) until the transaction ends: two requests with the same
     * link cannot both find it unused.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    boolean existsByUserIdAndCreatedAtAfter(UUID userId, OffsetDateTime since);

    /** Invalidates the pending links of a user, so only the newest one works. */
    @Modifying
    @Query("UPDATE PasswordResetToken t SET t.usedAt = :now WHERE t.user.id = :userId AND t.usedAt IS NULL")
    int invalidatePending(@Param("userId") UUID userId, @Param("now") OffsetDateTime now);

    @Modifying
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiresAt < :before OR t.usedAt < :before")
    int deleteFinishedBefore(@Param("before") OffsetDateTime before);
}
