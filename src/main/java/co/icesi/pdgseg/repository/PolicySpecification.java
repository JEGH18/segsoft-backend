package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import org.springframework.data.jpa.domain.Specification;

public final class PolicySpecification {

    private PolicySpecification() {}

    public static Specification<Policy> withFramework(Framework framework) {
        return (root, query, cb) ->
            framework == null ? null : cb.equal(root.get("framework"), framework);
    }

    public static Specification<Policy> withCategory(Category category) {
        return (root, query, cb) ->
            category == null ? null : cb.equal(root.get("category"), category);
    }

    public static Specification<Policy> withStatus(PolicyStatus status) {
        return (root, query, cb) ->
            status == null ? null : cb.equal(root.get("status"), status);
    }

    public static Specification<Policy> withNameContaining(String name) {
        return (root, query, cb) ->
            (name == null || name.isBlank()) ? null
                : cb.like(cb.lower(root.get("name")), "%" + name.toLowerCase() + "%");
    }
}
