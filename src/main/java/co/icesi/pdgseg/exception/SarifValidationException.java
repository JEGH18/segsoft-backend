package co.icesi.pdgseg.exception;

import java.util.List;

/**
 * A generated SARIF document failed validation against the official SARIF
 * 2.1.0 schema. It is a server-side defect (HTTP 500): the document is
 * discarded and never served.
 */
public class SarifValidationException extends RuntimeException {

    private final List<String> violations;

    public SarifValidationException(List<String> violations) {
        super("El documento SARIF generado no cumple el schema SARIF 2.1.0 (" + violations.size() + " violaciones)");
        this.violations = List.copyOf(violations);
    }

    public List<String> getViolations() {
        return violations;
    }
}
