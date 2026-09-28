package co.icesi.pdgseg.dto.response;

public record Iso27002ControlResponse(
    String id,
    String title,
    String category,
    String implementationGuidance
) {}
