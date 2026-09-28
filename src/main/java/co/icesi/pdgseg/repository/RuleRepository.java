package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.Rule;
import co.icesi.pdgseg.entity.enums.RuleStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface RuleRepository extends JpaRepository<Rule, UUID> {

    List<Rule> findByPolicyIdInAndStatus(Collection<UUID> policyIds, RuleStatus status);

    Page<Rule> findByPolicyAndStatus(Policy policy, RuleStatus status, Pageable pageable);

    int countByPolicyAndStatus(Policy policy, RuleStatus status);

    @Query("SELECT r.policy.id, COUNT(r) FROM Rule r WHERE r.policy.id IN :policyIds AND r.status = 'ACTIVE' GROUP BY r.policy.id")
    List<Object[]> countActiveByPolicyIds(@Param("policyIds") List<UUID> policyIds);

    @Query("SELECT r.policy.id as policyId, COUNT(r) as rulesCount FROM Rule r WHERE r.policy.id IN :policyIds AND r.status = 'ACTIVE' GROUP BY r.policy.id")
    List<PolicyRuleCountProjection> countEnabledRulesByPolicyIds(@Param("policyIds") Collection<UUID> policyIds);
}
