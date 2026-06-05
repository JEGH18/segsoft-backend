package co.icesi.pdgseg.repository.spec;

import co.icesi.pdgseg.entity.Finding;
import co.icesi.pdgseg.entity.enums.SeverityLevel;
import org.springframework.data.jpa.domain.Specification;

import java.util.Collection;
import java.util.UUID;

public final class FindingSpecifications {

    private FindingSpecifications() {
    }

    public static Specification<Finding> analysisIdEquals(UUID analysisId) {
        return (root, query, cb) -> cb.equal(root.get("analysis").get("id"), analysisId);
    }

    public static Specification<Finding> severityIn(Collection<SeverityLevel> severities) {
        return (root, query, cb) -> root.get("severity").in(severities);
    }

    public static Specification<Finding> categoryIn(Collection<String> categories) {
        return (root, query, cb) -> root.get("category").in(categories);
    }

    public static Specification<Finding> policyIdEquals(UUID policyId) {
        return (root, query, cb) -> cb.equal(root.get("policy").get("id"), policyId);
    }

    public static Specification<Finding> filePathContains(String filePath) {
        String normalized = "%" + filePath.toLowerCase() + "%";
        return (root, query, cb) -> cb.like(cb.lower(root.get("filePath")), normalized);
    }
}
