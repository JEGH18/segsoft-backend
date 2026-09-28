package co.icesi.pdgseg.dto.engine;

import java.util.List;

public record ExecuteRuleResponse(
        List<EngineFindingResponse> findings,
        List<EngineRuleErrorResponse> errors
) {
}
