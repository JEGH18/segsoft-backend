package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.enums.InventoryStatus;
import co.icesi.pdgseg.entity.enums.RepositoryStatus;
import co.icesi.pdgseg.entity.enums.SourceType;
import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "repositories")
public class Repository {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private RepositoryStatus status = RepositoryStatus.UPLOADING;

    @Enumerated(EnumType.STRING)
    @Column(name = "inventory_status", nullable = false, length = 30)
    private InventoryStatus inventoryStatus = InventoryStatus.PENDING;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 20)
    private SourceType sourceType;

    @Column(name = "original_name", nullable = false, length = 500)
    private String originalName;

    @Column(name = "git_url", length = 1000)
    private String gitUrl;

    @Column(length = 200)
    private String branch;

    @Column(name = "path_in_sandbox", length = 500)
    private String pathInSandbox;

    @Column(name = "sha256_archive", length = 64)
    private String sha256Archive;

    @Column(name = "file_count")
    private Integer fileCount;

    @Column(name = "excluded_count", nullable = false)
    private long excludedCount = 0;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;

    public Repository() {}

    public UUID getId() { return id; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public RepositoryStatus getStatus() { return status; }
    public void setStatus(RepositoryStatus status) { this.status = status; }

    public InventoryStatus getInventoryStatus() { return inventoryStatus; }
    public void setInventoryStatus(InventoryStatus inventoryStatus) { this.inventoryStatus = inventoryStatus; }

    public SourceType getSourceType() { return sourceType; }
    public void setSourceType(SourceType sourceType) { this.sourceType = sourceType; }

    public String getOriginalName() { return originalName; }
    public void setOriginalName(String originalName) { this.originalName = originalName; }

    public String getGitUrl() { return gitUrl; }
    public void setGitUrl(String gitUrl) { this.gitUrl = gitUrl; }

    public String getBranch() { return branch; }
    public void setBranch(String branch) { this.branch = branch; }

    public String getPathInSandbox() { return pathInSandbox; }
    public void setPathInSandbox(String pathInSandbox) { this.pathInSandbox = pathInSandbox; }

    public String getSha256Archive() { return sha256Archive; }
    public void setSha256Archive(String sha256Archive) { this.sha256Archive = sha256Archive; }

    public Integer getFileCount() { return fileCount; }
    public void setFileCount(Integer fileCount) { this.fileCount = fileCount; }

    public long getExcludedCount() { return excludedCount; }
    public void setExcludedCount(long excludedCount) { this.excludedCount = excludedCount; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public OffsetDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(OffsetDateTime expiresAt) { this.expiresAt = expiresAt; }

    public UUID getUserId() { return user != null ? user.getId() : null; }
    public User getOwner() { return user; }
}
