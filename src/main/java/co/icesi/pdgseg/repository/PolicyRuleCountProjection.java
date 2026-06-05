package co.icesi.pdgseg.repository;

import java.util.UUID;

public interface PolicyRuleCountProjection {
    UUID getPolicyId();
    Long getRulesCount();
}
