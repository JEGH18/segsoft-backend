package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.PolicySet;
import co.icesi.pdgseg.entity.enums.PolicySetStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface PolicySetRepository extends JpaRepository<PolicySet, UUID> {
    List<PolicySet> findByStatusOrderByCreatedAtDesc(PolicySetStatus status);

    // search defaults to "" (never null) so ContainingIgnoreCase matches every name.
    Page<PolicySet> findByStatusAndNameContainingIgnoreCase(PolicySetStatus status, String search, Pageable pageable);
}
