package co.icesi.pdgseg.repository;

import co.icesi.pdgseg.entity.Iso27002Control;
import co.icesi.pdgseg.entity.enums.Iso27002Category;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface Iso27002ControlRepository extends JpaRepository<Iso27002Control, String> {
    List<Iso27002Control> findAllByOrderByCategoryAscIdAsc();
    List<Iso27002Control> findByCategoryOrderById(Iso27002Category category);
    List<Iso27002Control> findByCorrespondingAnnexAControlOrderById(String correspondingAnnexAControl);
    List<Iso27002Control> findByCategoryAndCorrespondingAnnexAControlOrderById(
        Iso27002Category category, String correspondingAnnexAControl);
}
