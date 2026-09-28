package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.enums.Iso27002Category;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Reference catalog of ISO/IEC 27002:2022 controls. Distinct from
 * FrameworkControl (which holds exactly one control per (framework,
 * category) to auto-derive a Policy's control_id): this is the broader,
 * browsable 27002 catalog, and correspondingAnnexAControl is what lets a
 * Policy's controlId (ISO/IEC 27001 Annex A) be validated against a chosen
 * implementationGuideId here -- ISO/IEC 27001:2022 and 27002:2022 share
 * identical control numbering, so this is always "A." + id.
 */
@Entity
@Table(name = "iso27002_controls")
public class Iso27002Control {

    @Id
    private String id;

    @Column(nullable = false)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Iso27002Category category;

    @Column(name = "implementation_guidance", nullable = false, columnDefinition = "text")
    private String implementationGuidance;

    @Column(name = "corresponding_annex_a_control", nullable = false, length = 20)
    private String correspondingAnnexAControl;

    public String getId() { return id; }
    public String getTitle() { return title; }
    public Iso27002Category getCategory() { return category; }
    public String getImplementationGuidance() { return implementationGuidance; }
    public String getCorrespondingAnnexAControl() { return correspondingAnnexAControl; }
}
