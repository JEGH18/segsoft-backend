package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.RefreshTokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;

public interface RefreshTokenBlacklistRepository extends JpaRepository<RefreshTokenBlacklist, String> {

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshTokenBlacklist r WHERE r.expiresAt < CURRENT_TIMESTAMP")
    void deleteExpiredTokens();

    @Modifying
    @Transactional
    @Query(value = "INSERT INTO refresh_token_blacklist (token_hash, expires_at) VALUES (:tokenHash, :expiresAt) ON CONFLICT DO NOTHING",
           nativeQuery = true)
    void insertIgnoreConflict(@Param("tokenHash") String tokenHash, @Param("expiresAt") OffsetDateTime expiresAt);
}
