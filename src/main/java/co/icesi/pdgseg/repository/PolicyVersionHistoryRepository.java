package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.PolicyVersionHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface PolicyVersionHistoryRepository extends JpaRepository<PolicyVersionHistory, UUID> {
    List<PolicyVersionHistory> findByPolicyIdOrderByVersionDesc(UUID policyId);
}
