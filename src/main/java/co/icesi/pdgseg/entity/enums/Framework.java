package co.icesi.pdgseg.entity.enums;

public enum Framework {
    ISO_27001,
    OWASP_TOP_10_2021,
    OWASP_ASVS,
    NIST_SP_800_53,
    // Team-defined policies with no external standard behind them -- the only
    // framework without a control catalog, so control_id stays free text.
    CUSTOM,
    DEVSECOPS
}
