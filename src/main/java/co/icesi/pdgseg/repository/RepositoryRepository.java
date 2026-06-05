package co.icesi.pdgseg.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RepositoryRepository extends JpaRepository<co.icesi.pdgseg.entity.Repository, UUID> {
}
