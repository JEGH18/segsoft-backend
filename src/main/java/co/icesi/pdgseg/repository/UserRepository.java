package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    Optional<User> findByUsernameAndEnabledTrue(String username);
    boolean existsByUsernameIgnoreCase(String username);

    /** What every authenticated request checks: five columns, without loading the roles. */
    interface AccessState {
        Boolean getEnabled();
        Integer getTokenVersion();
        OffsetDateTime getLockedUntil();
        String getEmail();
        OffsetDateTime getEmailVerifiedAt();
    }

    @Query("SELECT u.enabled AS enabled, u.tokenVersion AS tokenVersion, u.lockedUntil AS lockedUntil, u.email AS email, "
            + "u.emailVerifiedAt AS emailVerifiedAt FROM User u WHERE u.username = :username")
    Optional<AccessState> findAccessStateByUsername(@Param("username") String username);

    boolean existsByEmailIgnoreCase(String email);
    Optional<User> findByEmailIgnoreCase(String email);

    /**
     * Deletes the self-registered accounts whose email was never verified, so an abandoned
     * registration does not keep a username or an email taken forever. Such accounts never logged
     * in, so they own no repositories, analyses or reports.
     */
    @Modifying
    @Query(value = "DELETE FROM users WHERE email IS NOT NULL AND email_verified_at IS NULL AND created_at < :before",
           nativeQuery = true)
    int deleteUnverifiedCreatedBefore(@Param("before") OffsetDateTime before);
}
