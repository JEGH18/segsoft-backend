package co.icesi.pdgseg.dto.request;

import co.icesi.pdgseg.entity.enums.RuleType;
import co.icesi.pdgseg.entity.enums.Severity;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Map;

public record CreateRuleRequest(
    @NotNull RuleType type,
    @NotNull Map<String, Object> payload,
    @Size(max = 100) String targetArtifact,
    List<String> languages,
    @NotNull Severity severity,
    @Size(max = 20) String cweId
) {}
