package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "framework_controls")
public class FrameworkControl {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Framework framework;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Category category;

    @Column(name = "control_id", nullable = false)
    private String controlId;

    @Column(name = "control_name", nullable = false)
    private String controlName;

    public UUID getId() { return id; }
    public Framework getFramework() { return framework; }
    public Category getCategory() { return category; }
    public String getControlId() { return controlId; }
    public String getControlName() { return controlName; }
}
