package co.icesi.pdgseg.dto.response;

public record CategoryCoverageItem(
    String category,
    int activePolicies,
    int executablePolicies
) {}
