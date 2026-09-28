package co.icesi.pdgseg.dto.snapshot;

import java.util.List;

public record AnalysisSnapshotDto(
        List<PolicySnapshotDto> policies
) {
    public int rulesTotal() {
        return policies == null ? 0 : policies.stream().mapToInt(policy -> policy.rules().size()).sum();
    }
}
