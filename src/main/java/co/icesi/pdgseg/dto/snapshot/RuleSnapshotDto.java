package co.icesi.pdgseg.dto.snapshot;

import java.util.Map;
import java.util.UUID;

public record RuleSnapshotDto(
        UUID ruleId,
        String type,
        String severity,
        String category,
        Map<String, Object> payload
) {
}
