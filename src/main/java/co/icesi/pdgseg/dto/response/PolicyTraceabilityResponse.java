package co.icesi.pdgseg.dto.response;

import java.util.UUID;

/**
 * Escenario 5 de "Derivar políticas del catálogo a partir de ISO/IEC
 * 27002": la cadena de trazabilidad de una política -- el control del
 * Anexo A de ISO/IEC 27001 y, cuando existe, la guía de implementación de
 * ISO/IEC 27002 correspondiente.
 */
public record PolicyTraceabilityResponse(
    UUID policyId,
    String policyName,
    String framework,
    AnnexAControl annexAControl,
    ImplementationGuide implementationGuide
) {
    public record AnnexAControl(String id, String name) {}

    public record ImplementationGuide(String id, String title, String guidance) {}
}
