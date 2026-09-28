package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.RepositoryFile;
import co.icesi.pdgseg.entity.enums.ArtifactType;

import java.util.UUID;

public record RepositoryFileResponse(
        UUID id,
        String path,
        String language,
        ArtifactType artifactType,
        Long sizeBytes,
        String sha256
) {
    public static RepositoryFileResponse from(RepositoryFile file) {
        return new RepositoryFileResponse(
                file.getId(),
                file.getPath(),
                file.getLanguage(),
                file.getArtifactType(),
                file.getSizeBytes(),
                file.getSha256()
        );
    }
}
