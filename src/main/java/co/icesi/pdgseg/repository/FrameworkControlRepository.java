package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.FrameworkControl;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FrameworkControlRepository extends JpaRepository<FrameworkControl, java.util.UUID> {

    List<FrameworkControl> findByFrameworkOrderByCategory(Framework framework);

    Optional<FrameworkControl> findByFrameworkAndCategory(Framework framework, Category category);
}
