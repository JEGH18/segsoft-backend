package co.icesi.pdgseg.dto.response;

import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;

import java.util.UUID;

public record PolicySetPolicySummary(
    UUID id,
    String name,
    Framework framework,
    Category category
) {}
