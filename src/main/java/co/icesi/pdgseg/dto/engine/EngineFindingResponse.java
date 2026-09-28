package co.icesi.pdgseg.dto.engine;

public record EngineFindingResponse(
        String filePath,
        Integer lineNumber,
        String evidenceSnippet,
        String fileSha256,
        String category,
        String severity,
        String cweId,
        String suggestedAction
) {
}
