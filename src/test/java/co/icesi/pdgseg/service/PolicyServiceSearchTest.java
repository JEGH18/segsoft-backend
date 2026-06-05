package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.response.PolicyResponse;
import co.icesi.pdgseg.entity.Policy;
import co.icesi.pdgseg.entity.enums.Category;
import co.icesi.pdgseg.entity.enums.Framework;
import co.icesi.pdgseg.entity.enums.PolicyStatus;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.PolicyRepository;
import co.icesi.pdgseg.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PolicyServiceSearchTest {

    @Mock PolicyRepository policyRepository;
    @Mock UserRepository userRepository;
    @Mock JdbcTemplate jdbcTemplate;
    @Mock ObjectMapper objectMapper;

    @InjectMocks PolicyService policyService;

    private Policy stubPolicy(String name) {
        Policy p = new Policy();
        p.setId(UUID.randomUUID());
        p.setName(name);
        p.setDescription("Descripción con la longitud mínima requerida de veinte caracteres.");
        p.setCategory(Category.SQL_INJECTION);
        p.setFramework(Framework.OWASP_TOP_10_2021);
        p.setStatus(PolicyStatus.ACTIVE);
        p.setVersion(1);
        p.setWeight(50);
        p.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return p;
    }

    @Test
    void search_noFilters_returnsPagedPolicies() {
        Page<Policy> page = new PageImpl<>(
            List.of(stubPolicy("P1"), stubPolicy("P2")),
            PageRequest.of(0, 10), 2);
        when(policyRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(page);

        Page<PolicyResponse> result = policyService.search(null, null, null, null, PageRequest.of(0, 10));

        assertThat(result.getTotalElements()).isEqualTo(2);
        assertThat(result.getContent()).hasSize(2);
    }

    @Test
    void search_emptyBank_returnsEmptyPage() {
        Page<Policy> empty = new PageImpl<>(List.of(), PageRequest.of(0, 10), 0);
        when(policyRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(empty);

        Page<PolicyResponse> result = policyService.search(null, null, null, null, PageRequest.of(0, 10));

        assertThat(result.getTotalElements()).isZero();
        assertThat(result.getContent()).isEmpty();
    }

    @Test
    void search_withCategoryAndStatus_delegatesToRepository() {
        Policy p = stubPolicy("SQL Policy");
        Page<Policy> page = new PageImpl<>(List.of(p), PageRequest.of(0, 10), 1);
        when(policyRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(page);

        Page<PolicyResponse> result = policyService.search(
            null, Category.SQL_INJECTION, PolicyStatus.ACTIVE, null, PageRequest.of(0, 10));

        assertThat(result.getContent().get(0).category()).isEqualTo(Category.SQL_INJECTION);
    }

    @Test
    void search_paginated_respectsPageMetadata() {
        List<Policy> batch = List.of(stubPolicy("P1"), stubPolicy("P2"), stubPolicy("P3"));
        Page<Policy> page = new PageImpl<>(batch, PageRequest.of(1, 3), 10);
        when(policyRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(page);

        Page<PolicyResponse> result = policyService.search(null, null, null, null, PageRequest.of(1, 3));

        assertThat(result.getTotalElements()).isEqualTo(10);
        assertThat(result.getTotalPages()).isEqualTo(4);
        assertThat(result.getNumber()).isEqualTo(1);
    }

    @Test
    void findById_existingId_returnsResponse() {
        Policy p = stubPolicy("Mi Política");
        when(policyRepository.findById(p.getId())).thenReturn(Optional.of(p));

        PolicyResponse response = policyService.findById(p.getId());

        assertThat(response.name()).isEqualTo("Mi Política");
        assertThat(response.status()).isEqualTo(PolicyStatus.ACTIVE);
    }

    @Test
    void findById_nonExistentId_throwsResourceNotFoundException() {
        UUID unknownId = UUID.randomUUID();
        when(policyRepository.findById(unknownId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> policyService.findById(unknownId))
            .isInstanceOf(ResourceNotFoundException.class)
            .hasMessageContaining(unknownId.toString());
    }
}
