package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.ApiToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApiTokenRepository extends JpaRepository<ApiToken, UUID> {
    Optional<ApiToken> findByTokenHash(String tokenHash);
    List<ApiToken> findAllByOrderByCreatedAtDesc();
}
