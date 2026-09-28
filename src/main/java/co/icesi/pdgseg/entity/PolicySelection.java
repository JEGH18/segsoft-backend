package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.converter.UuidListJsonConverter;
import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "policy_selections")
public class PolicySelection {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repository_id", nullable = false, unique = true)
    private Repository repository;

    @Convert(converter = UuidListJsonConverter.class)
    @Column(name = "selected_policy_ids", nullable = false, columnDefinition = "text")
    private List<UUID> selectedPolicyIds = new ArrayList<>();

    // Set only when this selection was populated by applying a Policy Set
    // (PDGSEGSOFT-276, out of this HU's scope). Nullable: most selections
    // are built manually. Used to know which repositories/analyses a Policy
    // Set is "in use by", for the archive-block check (Gherkin escenario 5).
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_set_id")
    private PolicySet policySet;

    @Column(nullable = false)
    private Integer version = 0;

    // "MANUAL" | "POLICY_SET:{policySetId}:{version}" |
    // "MANUAL_ADJUSTMENT (from POLICY_SET:{policySetId}:{version})".
    // Unlike the policySet FK above (which is cleared whenever the
    // selection is edited manually), this keeps the origin readable even
    // after that link is dropped -- it's what Gherkin escenario 5 of
    // "Aplicar un Policy Set a un repositorio" checks for.
    @Column(nullable = false, length = 255)
    private String source = "MANUAL";

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        if (this.createdAt == null) this.createdAt = now;
        if (this.updatedAt == null) this.updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = OffsetDateTime.now();
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public Repository getRepository() { return repository; }
    public void setRepository(Repository repository) { this.repository = repository; }

    public List<UUID> getSelectedPolicyIds() { return selectedPolicyIds; }
    public void setSelectedPolicyIds(List<UUID> selectedPolicyIds) { this.selectedPolicyIds = selectedPolicyIds; }

    public PolicySet getPolicySet() { return policySet; }
    public void setPolicySet(PolicySet policySet) { this.policySet = policySet; }

    public Integer getVersion() { return version; }
    public void setVersion(Integer version) { this.version = version; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public User getCreatedBy() { return createdBy; }
    public void setCreatedBy(User createdBy) { this.createdBy = createdBy; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public OffsetDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(OffsetDateTime updatedAt) { this.updatedAt = updatedAt; }
}
