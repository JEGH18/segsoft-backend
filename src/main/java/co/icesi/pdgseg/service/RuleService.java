package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreateRuleRequest;
import co.icesi.pdgseg.dto.response.RuleResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.Rule;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.entity.enums.RuleStatus;
import co.icesi.pdgseg.entity.enums.RuleType;
import co.icesi.pdgseg.exception.InvalidRulePayloadException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Service
public class RuleService {

    private final RuleRepository ruleRepository;
    private final PolicyRepository policyRepository;

    public RuleService(RuleRepository ruleRepository, PolicyRepository policyRepository) {
        this.ruleRepository = ruleRepository;
        this.policyRepository = policyRepository;
    }

    @Transactional
    public RuleResponse create(UUID policyId, CreateRuleRequest request) {
        Policy policy = policyRepository.findById(policyId)
            .orElseThrow(() -> new ResourceNotFoundException(
                "Política no encontrada con id: " + policyId));

        if (policy.getStatus() != PolicyStatus.ACTIVE) {
            throw new InvalidRulePayloadException(
                "Solo se pueden añadir reglas a políticas ACTIVE. Estado actual: " + policy.getStatus());
        }

        validatePayload(request.type(), request.payload());

        Rule rule = new Rule();
        rule.setPolicy(policy);
        rule.setType(request.type());
        rule.setPayload(request.payload());
        rule.setTargetArtifact(request.targetArtifact());
        rule.setLanguages(request.languages() != null ? request.languages() : new ArrayList<>());
        rule.setSeverity(request.severity());
        rule.setCweId(request.cweId());
        rule.setCategory(policy.getCategory() != null ? policy.getCategory().name() : null);
        rule.setStatus(RuleStatus.ACTIVE);
        rule.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));

        Rule saved = ruleRepository.saveAndFlush(rule);
        return toResponse(saved);
    }

    public Page<RuleResponse> listByPolicy(UUID policyId, Pageable pageable) {
        Policy policy = policyRepository.findById(policyId)
            .orElseThrow(() -> new ResourceNotFoundException(
                "Política no encontrada con id: " + policyId));

        return ruleRepository.findByPolicyAndStatus(policy, RuleStatus.ACTIVE, pageable)
            .map(RuleService::toResponse);
    }

    @Transactional
    public RuleResponse archive(UUID ruleId) {
        Rule rule = ruleRepository.findById(ruleId)
            .orElseThrow(() -> new ResourceNotFoundException(
                "Regla no encontrada con id: " + ruleId));

        rule.setStatus(RuleStatus.ARCHIVED);
        return toResponse(ruleRepository.saveAndFlush(rule));
    }

    private void validatePayload(RuleType type, Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) {
            throw new InvalidRulePayloadException("El payload no puede estar vacío");
        }
        if (type == RuleType.PATTERN_REGEX) {
            Object rawPattern = payload.get("pattern");
            if (!(rawPattern instanceof String pattern) || pattern.isBlank()) {
                throw new InvalidRulePayloadException(
                    "El payload de PATTERN_REGEX requiere el campo 'pattern' de tipo String");
            }
            try {
                Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                throw new InvalidRulePayloadException(
                    "Patrón regex inválido en posición " + e.getIndex() + ": " + e.getDescription());
            }
        }
    }

    public static RuleResponse toResponse(Rule r) {
        return new RuleResponse(
            r.getId(),
            r.getPolicy().getId(),
            r.getType(),
            r.getPayload(),
            r.getTargetArtifact(),
            r.getLanguages(),
            r.getSeverity(),
            r.getCweId(),
            r.getCategory(),
            r.getStatus(),
            r.getCreatedAt()
        );
    }
}
