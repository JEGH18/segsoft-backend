package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.Repository;
import co.icesi.pdgseg.entity.enums.RepositoryStatus;
import co.icesi.pdgseg.entity.enums.SourceType;

import java.time.OffsetDateTime;
import java.util.UUID;

public record RepositoryResponse(
        UUID id,
        RepositoryStatus status,
        SourceType sourceType,
        String originalName,
        String gitUrl,
        String branch,
        Integer fileCount,
        String errorMessage,
        OffsetDateTime createdAt,
        OffsetDateTime expiresAt
) {
    public static RepositoryResponse from(Repository r) {
        return new RepositoryResponse(
                r.getId(),
                r.getStatus(),
                r.getSourceType(),
                r.getOriginalName(),
                r.getGitUrl(),
                r.getBranch(),
                r.getFileCount(),
                r.getErrorMessage(),
                r.getCreatedAt(),
                r.getExpiresAt()
        );
    }
}
