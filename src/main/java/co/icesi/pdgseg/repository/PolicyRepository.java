package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.enums.Framework;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, UUID>,
        JpaSpecificationExecutor<Policy> {

    boolean existsByNameAndFramework(String name, Framework framework);

    List<Policy> findByIdIn(List<UUID> ids);
}
