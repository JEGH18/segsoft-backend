package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.RuleStatus;
import co.icesi.pdgseg.entity.enums.RuleType;
import co.icesi.pdgseg.entity.enums.Severity;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record RuleResponse(
    UUID id,
    UUID policyId,
    RuleType type,
    Map<String, Object> payload,
    String targetArtifact,
    List<String> languages,
    Severity severity,
    String cweId,
    String category,
    RuleStatus status,
    OffsetDateTime createdAt
) {}
