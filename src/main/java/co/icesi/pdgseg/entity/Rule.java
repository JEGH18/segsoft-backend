package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.converter.MapJsonConverter;
import co.icesi.pdgseg.entity.converter.StringListJsonConverter;
import co.icesi.pdgseg.entity.enums.RuleStatus;
import co.icesi.pdgseg.entity.enums.RuleType;
import co.icesi.pdgseg.entity.enums.Severity;
import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "rules")
public class Rule {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private RuleType type;

    @Convert(converter = MapJsonConverter.class)
    @Column(nullable = false, columnDefinition = "text")
    private Map<String, Object> payload;

    @Column(name = "target_artifact", length = 100)
    private String targetArtifact;

    @Convert(converter = StringListJsonConverter.class)
    @Column(columnDefinition = "text")
    private List<String> languages = new ArrayList<>();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Severity severity;

    @Column(name = "cwe_id", length = 20)
    private String cweId;

    @Column(length = 50)
    private String category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RuleStatus status = RuleStatus.ACTIVE;

    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    public Rule() {}

    public UUID getId() { return id; }
    public Policy getPolicy() { return policy; }
    public void setPolicy(Policy policy) { this.policy = policy; }
    public RuleType getType() { return type; }
    public void setType(RuleType type) { this.type = type; }
    public Map<String, Object> getPayload() { return payload; }
    public void setPayload(Map<String, Object> payload) { this.payload = payload; }
    public String getTargetArtifact() { return targetArtifact; }
    public void setTargetArtifact(String targetArtifact) { this.targetArtifact = targetArtifact; }
    public List<String> getLanguages() { return languages; }
    public void setLanguages(List<String> languages) { this.languages = languages; }
    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public String getCweId() { return cweId; }
    public void setCweId(String cweId) { this.cweId = cweId; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public RuleStatus getStatus() { return status; }
    public void setStatus(RuleStatus status) { this.status = status; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }
}
