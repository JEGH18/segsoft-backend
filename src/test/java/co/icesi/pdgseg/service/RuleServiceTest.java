package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreateRuleRequest;
import co.icesi.pdgseg.dto.response.RuleResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.Rule;
import co.icesi.pdgseg.entity.enums.*;
import co.icesi.pdgseg.exception.InvalidRulePayloadException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.RuleRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RuleServiceTest {

    @Mock RuleRepository ruleRepository;
    @Mock PolicyRepository policyRepository;

    @InjectMocks RuleService ruleService;

    private Policy activePolicy() {
        Policy p = new Policy();
        p.setId(UUID.randomUUID());
        p.setName("SQL Policy");
        p.setCategory(Category.SQL_INJECTION);
        p.setStatus(PolicyStatus.ACTIVE);
        return p;
    }

    private Rule savedRule(Policy p, RuleType type, Map<String, Object> payload) {
        Rule r = new Rule();
        r.setPolicy(p);
        r.setType(type);
        r.setPayload(payload);
        r.setLanguages(List.of("java"));
        r.setSeverity(Severity.HIGH);
        r.setStatus(RuleStatus.ACTIVE);
        r.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return r;
    }

    @Test
    void create_validRegexPayload_returnsCreatedRule() {
        Policy policy = activePolicy();
        Map<String, Object> payload = Map.of("pattern", "(?i)(api[_-]?key)\\s*=");
        CreateRuleRequest req = new CreateRuleRequest(
            RuleType.PATTERN_REGEX, payload, null, List.of("java"), Severity.HIGH, "CWE-798");

        when(policyRepository.findById(policy.getId())).thenReturn(Optional.of(policy));
        when(ruleRepository.saveAndFlush(any())).thenAnswer(inv -> savedRule(policy, RuleType.PATTERN_REGEX, payload));

        RuleResponse response = ruleService.create(policy.getId(), req);

        assertThat(response.type()).isEqualTo(RuleType.PATTERN_REGEX);
        assertThat(response.severity()).isEqualTo(Severity.HIGH);
        assertThat(response.status()).isEqualTo(RuleStatus.ACTIVE);
    }

    @Test
    void create_invalidRegexPattern_throwsInvalidRulePayloadException() {
        Policy policy = activePolicy();
        Map<String, Object> payload = Map.of("pattern", "[invalid(regex");
        CreateRuleRequest req = new CreateRuleRequest(
            RuleType.PATTERN_REGEX, payload, null, null, Severity.MEDIUM, null);

        when(policyRepository.findById(policy.getId())).thenReturn(Optional.of(policy));

        assertThatThrownBy(() -> ruleService.create(policy.getId(), req))
            .isInstanceOf(InvalidRulePayloadException.class)
            .hasMessageContaining("Patrón regex inválido en posición");
    }

    @Test
    void create_missingPatternField_throwsInvalidRulePayloadException() {
        Policy policy = activePolicy();
        Map<String, Object> payload = Map.of("description", "no pattern here");
        CreateRuleRequest req = new CreateRuleRequest(
            RuleType.PATTERN_REGEX, payload, null, null, Severity.LOW, null);

        when(policyRepository.findById(policy.getId())).thenReturn(Optional.of(policy));

        assertThatThrownBy(() -> ruleService.create(policy.getId(), req))
            .isInstanceOf(InvalidRulePayloadException.class)
            .hasMessageContaining("'pattern'");
    }

    @Test
    void create_nonExistentPolicy_throwsResourceNotFoundException() {
        UUID unknownId = UUID.randomUUID();
        Map<String, Object> payload = Map.of("pattern", "test");
        CreateRuleRequest req = new CreateRuleRequest(
            RuleType.PATTERN_REGEX, payload, null, null, Severity.LOW, null);

        when(policyRepository.findById(unknownId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> ruleService.create(unknownId, req))
            .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void create_archivedPolicy_throwsInvalidRulePayloadException() {
        Policy policy = activePolicy();
        policy.setStatus(PolicyStatus.ARCHIVED);
        Map<String, Object> payload = Map.of("pattern", "test");
        CreateRuleRequest req = new CreateRuleRequest(
            RuleType.PATTERN_REGEX, payload, null, null, Severity.LOW, null);

        when(policyRepository.findById(policy.getId())).thenReturn(Optional.of(policy));

        assertThatThrownBy(() -> ruleService.create(policy.getId(), req))
            .isInstanceOf(InvalidRulePayloadException.class)
            .hasMessageContaining("ARCHIVED");
    }

    @Test
    void archive_existingRule_changesStatusToArchived() {
        Policy policy = activePolicy();
        Rule rule = savedRule(policy, RuleType.PATTERN_REGEX, Map.of("pattern", "test"));
        UUID ruleId = UUID.randomUUID();

        when(ruleRepository.findById(ruleId)).thenReturn(Optional.of(rule));
        when(ruleRepository.saveAndFlush(any())).thenAnswer(inv -> {
            Rule r = inv.getArgument(0);
            r.setStatus(RuleStatus.ARCHIVED);
            return r;
        });

        RuleResponse response = ruleService.archive(ruleId);

        assertThat(response.status()).isEqualTo(RuleStatus.ARCHIVED);
    }

    @Test
    void archive_nonExistentRule_throwsResourceNotFoundException() {
        UUID unknownId = UUID.randomUUID();
        when(ruleRepository.findById(unknownId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> ruleService.archive(unknownId))
            .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void create_configCheckWithValidPayload_persists() {
        Policy policy = activePolicy();
        policy.setCategory(Category.INSECURE_DATA_HANDLING);
        Map<String, Object> payload = Map.of(
            "checks", List.of(Map.of("key", "DEBUG", "not_value", "true")));
        CreateRuleRequest req = new CreateRuleRequest(
            RuleType.CONFIG_CHECK, payload, null, null, Severity.MEDIUM, null);

        when(policyRepository.findById(policy.getId())).thenReturn(Optional.of(policy));
        when(ruleRepository.saveAndFlush(any())).thenAnswer(inv ->
            savedRule(policy, RuleType.CONFIG_CHECK, payload));

        RuleResponse response = ruleService.create(policy.getId(), req);

        assertThat(response.type()).isEqualTo(RuleType.CONFIG_CHECK);
    }
}
