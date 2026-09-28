package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.converter.MapJsonConverter;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Snapshot of a Policy's full state at a given version, written just before
 * a PATCH is applied, so historical analyses that depended on an earlier
 * version stay traceable even after the policy evolves or is archived.
 */
@Entity
@Table(name = "policy_version_history")
public class PolicyVersionHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @Column(nullable = false)
    private Integer version;

    @Column(nullable = false, length = 200)
    private String name;

    @Column(columnDefinition = "text")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private Category category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private Framework framework;

    @Column(name = "control_id", length = 100)
    private String controlId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private PolicyStatus status;

    @Column(nullable = false)
    private Integer weight;

    @Convert(converter = MapJsonConverter.class)
    @Column(columnDefinition = "text")
    private Map<String, Object> applicability;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "changed_by")
    private User changedBy;

    @Column(name = "changed_at", nullable = false, updatable = false)
    private OffsetDateTime changedAt;

    @PrePersist
    void onCreate() {
        if (this.changedAt == null) {
            this.changedAt = OffsetDateTime.now();
        }
    }

    public PolicyVersionHistory() {}

    public static PolicyVersionHistory snapshotOf(Policy policy, User changedBy) {
        PolicyVersionHistory snapshot = new PolicyVersionHistory();
        snapshot.policy = policy;
        snapshot.version = policy.getVersion();
        snapshot.name = policy.getName();
        snapshot.description = policy.getDescription();
        snapshot.category = policy.getCategory();
        snapshot.framework = policy.getFramework();
        snapshot.controlId = policy.getControlId();
        snapshot.status = policy.getStatus();
        snapshot.weight = policy.getWeight();
        snapshot.applicability = policy.getApplicability();
        snapshot.changedBy = changedBy;
        return snapshot;
    }

    public UUID getId() { return id; }
    public Policy getPolicy() { return policy; }
    public Integer getVersion() { return version; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public Category getCategory() { return category; }
    public Framework getFramework() { return framework; }
    public String getControlId() { return controlId; }
    public PolicyStatus getStatus() { return status; }
    public Integer getWeight() { return weight; }
    public Map<String, Object> getApplicability() { return applicability; }
    public User getChangedBy() { return changedBy; }
    public OffsetDateTime getChangedAt() { return changedAt; }
}
