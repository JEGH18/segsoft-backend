package co.icesi.pdgseg.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Reference catalog of NIST SP 800-53 controls, grouped by family (AC, AU,
 * IA, SC, SI...). Distinct from FrameworkControl: that table holds exactly
 * one control per (framework, category) used to auto-derive a Policy's
 * control_id; this one is the broader, browsable NIST catalog exposed via
 * GET /api/v1/frameworks/nist/controls.
 */
@Entity
@Table(name = "nist_controls")
public class NistControl {

    @Id
    private String id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String family;

    public String getId() { return id; }
    public String getTitle() { return title; }
    public String getFamily() { return family; }
}
