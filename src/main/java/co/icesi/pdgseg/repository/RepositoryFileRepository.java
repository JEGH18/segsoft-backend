package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.RepositoryFile;
import co.icesi.pdgseg.entity.enums.ArtifactType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface RepositoryFileRepository extends JpaRepository<RepositoryFile, UUID> {

    List<RepositoryFile> findByRepositoryId(UUID repositoryId);

    long countByRepositoryId(UUID repositoryId);

    void deleteByRepositoryId(UUID repositoryId);

    @Query("SELECT f FROM RepositoryFile f WHERE f.repository.id = :repoId " +
           "AND (:language IS NULL OR f.language = :language) " +
           "AND (:artifactType IS NULL OR f.artifactType = :artifactType)")
    Page<RepositoryFile> findByFilters(@Param("repoId") UUID repoId,
                                       @Param("language") String language,
                                       @Param("artifactType") ArtifactType artifactType,
                                       Pageable pageable);

    @Query("SELECT f.language, COUNT(f) FROM RepositoryFile f WHERE f.repository.id = :repoId GROUP BY f.language")
    List<Object[]> countGroupedByLanguage(@Param("repoId") UUID repoId);

    @Query("SELECT f.artifactType, COUNT(f) FROM RepositoryFile f WHERE f.repository.id = :repoId GROUP BY f.artifactType")
    List<Object[]> countGroupedByArtifactType(@Param("repoId") UUID repoId);
}
