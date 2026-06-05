package co.icesi.pdgseg.dto.snapshot;

import java.util.List;
import java.util.UUID;

public record PolicySnapshotDto(
        UUID policyId,
        String name,
        String category,
        List<RuleSnapshotDto> rules
) {
}
