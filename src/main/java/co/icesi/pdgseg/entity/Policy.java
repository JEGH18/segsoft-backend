package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.converter.MapJsonConverter;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(
    name = "policies",
    uniqueConstraints = @UniqueConstraint(
        name = "uq_policies_name_framework",
        columnNames = {"name", "framework"}
    )
)
public class Policy {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

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

    // Only meaningful for framework=ISO_27001: the ISO/IEC 27002:2022
    // implementation guide that elaborates on this policy's Annex A
    // controlId. NULL either because the framework isn't ISO_27001, or
    // because it's an ISO_27001 policy registered before this field existed
    // -- that second case is exactly what toResponse()'s computed
    // detailPending flag surfaces (see PolicyService), not a separate column.
    @Column(name = "implementation_guide_id", length = 20)
    private String implementationGuideId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private PolicyStatus status = PolicyStatus.ACTIVE;

    @Version
    @Column(nullable = false)
    private Integer version = 1;

    @Column(nullable = false)
    private Integer weight = 50;

    @Convert(converter = MapJsonConverter.class)
    @Column(columnDefinition = "text")
    private Map<String, Object> applicability = new HashMap<>();

    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;

    public Policy() {}

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Category getCategory() { return category; }
    public void setCategory(Category category) { this.category = category; }

    public Framework getFramework() { return framework; }
    public void setFramework(Framework framework) { this.framework = framework; }

    public String getControlId() { return controlId; }
    public void setControlId(String controlId) { this.controlId = controlId; }

    public String getImplementationGuideId() { return implementationGuideId; }
    public void setImplementationGuideId(String implementationGuideId) { this.implementationGuideId = implementationGuideId; }

    public PolicyStatus getStatus() { return status; }
    public void setStatus(PolicyStatus status) { this.status = status; }

    public Integer getVersion() { return version; }
    public void setVersion(Integer version) { this.version = version; }

    public Integer getWeight() { return weight; }
    public void setWeight(Integer weight) { this.weight = weight; }

    public Map<String, Object> getApplicability() { return applicability; }
    public void setApplicability(Map<String, Object> applicability) { this.applicability = applicability; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public User getCreatedBy() { return createdBy; }
    public void setCreatedBy(User createdBy) { this.createdBy = createdBy; }
}
