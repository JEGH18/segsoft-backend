package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.NistControl;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NistControlRepository extends JpaRepository<NistControl, String> {
    List<NistControl> findAllByOrderByFamilyAscIdAsc();
    List<NistControl> findByFamilyOrderById(String family);
}
