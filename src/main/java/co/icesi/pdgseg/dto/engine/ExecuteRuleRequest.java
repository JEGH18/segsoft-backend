package co.icesi.pdgseg.dto.engine;

import java.util.Map;

public record ExecuteRuleRequest(
        String ruleId,
        String type,
        Map<String, Object> payload,
        String artifactPath,
        String category,
        String severity,
        String cweId
) {
    // Sin category/severity/cweId, el motor Python nunca los recibe y cae en
    // sus propios valores por defecto ("UNKNOWN"/"MEDIUM") -- category se
    // salva porque el código de más abajo detecta el centinela "UNKNOWN" y
    // recupera el valor real, pero severity no tenía esa protección: cada
    // hallazgo terminaba reportado como MEDIUM sin importar la severidad
    // real de la regla, lo que además impedía que cualquier política
    // llegara a NON_COMPLIANT (eso solo dispara con HIGH/CRITICAL).
    public ExecuteRuleRequest(String ruleId, String type, Map<String, Object> payload, String artifactPath) {
        this(ruleId, type, payload, artifactPath, null, null, null);
    }
}
