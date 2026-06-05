package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.enums.ArtifactType;
import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "repository_files")
public class RepositoryFile {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repository_id", nullable = false)
    private Repository repository;

    @Column(nullable = false, length = 1000)
    private String path;

    @Column(nullable = false, length = 50)
    private String language = "unknown";

    @Enumerated(EnumType.STRING)
    @Column(name = "artifact_type", nullable = false, length = 50)
    private ArtifactType artifactType = ArtifactType.SOURCE_CODE;

    @Column(name = "size_bytes", nullable = false)
    private Long sizeBytes = 0L;

    @Column(nullable = false, length = 64)
    private String sha256;

    public RepositoryFile() {}

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public Repository getRepository() { return repository; }
    public void setRepository(Repository repository) { this.repository = repository; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getLanguage() { return language; }
    public void setLanguage(String language) { this.language = language; }

    public ArtifactType getArtifactType() { return artifactType; }
    public void setArtifactType(ArtifactType artifactType) { this.artifactType = artifactType; }

    public Long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(Long sizeBytes) { this.sizeBytes = sizeBytes; }

    public String getSha256() { return sha256; }
    public void setSha256(String sha256) { this.sha256 = sha256; }
}
