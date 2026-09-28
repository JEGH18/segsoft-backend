package co.icesi.pdgseg.entity;

import co.icesi.pdgseg.entity.enums.PolicyComplianceStatus;
import jakarta.persistence.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "policy_results")
public class PolicyResult {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analysis_id", nullable = false)
    private Analysis analysis;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private PolicyComplianceStatus status;

    @Column(name = "findings_count", nullable = false)
    private Integer findingsCount = 0;

    @Column(name = "high_or_critical_count", nullable = false)
    private Integer highOrCriticalCount = 0;

    @Column(name = "low_or_medium_count", nullable = false)
    private Integer lowOrMediumCount = 0;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @PrePersist
    void onCreate() {
        this.createdAt = OffsetDateTime.now();
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Analysis getAnalysis() {
        return analysis;
    }

    public void setAnalysis(Analysis analysis) {
        this.analysis = analysis;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public PolicyComplianceStatus getStatus() {
        return status;
    }

    public void setStatus(PolicyComplianceStatus status) {
        this.status = status;
    }

    public Integer getFindingsCount() {
        return findingsCount;
    }

    public void setFindingsCount(Integer findingsCount) {
        this.findingsCount = findingsCount;
    }

    public Integer getHighOrCriticalCount() {
        return highOrCriticalCount;
    }

    public void setHighOrCriticalCount(Integer highOrCriticalCount) {
        this.highOrCriticalCount = highOrCriticalCount;
    }

    public Integer getLowOrMediumCount() {
        return lowOrMediumCount;
    }

    public void setLowOrMediumCount(Integer lowOrMediumCount) {
        this.lowOrMediumCount = lowOrMediumCount;
    }
}
