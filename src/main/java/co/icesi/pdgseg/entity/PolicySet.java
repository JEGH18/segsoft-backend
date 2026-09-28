package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.enums.PolicySetStatus;
import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * A reusable, named bundle of active policies -- distinct from
 * PolicySelection, which is the (unnamed, per-repository) list of policies
 * a single repository is evaluated against. version is a plain counter
 * (not JPA @Version) that the service increments explicitly on every
 * composition/name/description change, so "version += 1 per edit" stays
 * deterministic regardless of how Hibernate would otherwise treat a
 * @ManyToMany collection mutation.
 */
@Entity
@Table(name = "policy_sets")
public class PolicySet {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 200)
    private String name;

    @Column(columnDefinition = "text")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private PolicySetStatus status = PolicySetStatus.ACTIVE;

    @Column(nullable = false)
    private Integer version = 1;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "policy_set_items",
        joinColumns = @JoinColumn(name = "policy_set_id"),
        inverseJoinColumns = @JoinColumn(name = "policy_id")
    )
    private Set<Policy> policies = new LinkedHashSet<>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;

    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at")
    private OffsetDateTime updatedAt;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        if (createdAt == null) createdAt = now;
        if (updatedAt == null) updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }

    public PolicySet() {}

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public PolicySetStatus getStatus() { return status; }
    public void setStatus(PolicySetStatus status) { this.status = status; }

    public Integer getVersion() { return version; }
    public void setVersion(Integer version) { this.version = version; }

    public Set<Policy> getPolicies() { return policies; }
    public void setPolicies(Set<Policy> policies) { this.policies = policies; }

    public User getCreatedBy() { return createdBy; }
    public void setCreatedBy(User createdBy) { this.createdBy = createdBy; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public OffsetDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(OffsetDateTime updatedAt) { this.updatedAt = updatedAt; }
}
