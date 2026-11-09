package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreateApiTokenRequest;
import co.icesi.pdgseg.dto.response.ApiTokenResponse;
import co.icesi.pdgseg.dto.response.CreateApiTokenResponse;
import co.icesi.pdgseg.entity.ApiToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.ConflictException;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.ApiTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import co.icesi.pdgseg.security.ApiTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

class ApiTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-09T12:00:00Z");
    private static final OffsetDateTime NOW_UTC = OffsetDateTime.ofInstant(NOW, ZoneOffset.UTC);

    private ApiTokenRepository apiTokenRepository;
    private UserRepository userRepository;
    private AuditService auditService;
    private ApiTokenService service;
    private User alice;

    @BeforeEach
    void setUp() {
        apiTokenRepository = mock(ApiTokenRepository.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);
        service = new ApiTokenService(apiTokenRepository, userRepository, auditService, Clock.fixed(NOW, ZoneOffset.UTC));

        alice = user("alice");
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        when(apiTokenRepository.save(any(ApiToken.class))).thenAnswer(inv -> {
            ApiToken t = inv.getArgument(0);
            ReflectionTestUtils.setField(t, "id", UUID.randomUUID());
            ReflectionTestUtils.setField(t, "createdAt", NOW_UTC);
            return t;
        });
    }

    private static User user(String username) {
        User u = new User();
        u.setUsername(username);
        return u;
    }

    private static ApiToken token(User owner, OffsetDateTime expiresAt) {
        ApiToken t = new ApiToken();
        ReflectionTestUtils.setField(t, "id", UUID.randomUUID());
        ReflectionTestUtils.setField(t, "createdAt", NOW_UTC.minusDays(1));
        t.setName("ci");
        t.setTokenPrefix("pdgseg_abcde");
        t.setCreatedBy(owner);
        t.setExpiresAt(expiresAt);
        return t;
    }

    @Test
    void create_returnsThePlaintextOnce_andStoresOnlyItsHashWithTheCallerAsOwner() {
        CreateApiTokenResponse created = service.create(new CreateApiTokenRequest("  GitHub Actions  ", null), "alice");

        ArgumentCaptor<ApiToken> saved = ArgumentCaptor.forClass(ApiToken.class);
        verify(apiTokenRepository).save(saved.capture());
        ApiToken stored = saved.getValue();

        assertThat(created.token()).startsWith(ApiTokens.PREFIX).hasSize(ApiTokens.PREFIX.length() + 43);
        assertThat(stored.getTokenHash()).isEqualTo(ApiTokens.hash(created.token())).doesNotContain(created.token());
        assertThat(stored.getTokenPrefix()).isEqualTo(created.token().substring(0, 12)).isEqualTo(created.tokenPrefix());
        assertThat(stored.getCreatedBy()).isSameAs(alice);
        assertThat(stored.getName()).isEqualTo("GitHub Actions");
        verify(auditService).record(eq("API_TOKEN_CREATED"), eq("alice"), isNull(), anyMap());
    }

    @Test
    void create_withoutExpiry_lasts90Days_andWithExpiry_lastsThatMany() {
        assertThat(service.create(new CreateApiTokenRequest("a", null), "alice").expiresAt())
                .isEqualTo(NOW_UTC.plusDays(90));
        assertThat(service.create(new CreateApiTokenRequest("b", 7), "alice").expiresAt())
                .isEqualTo(NOW_UTC.plusDays(7));
    }

    @Test
    void create_twoTokens_neverRepeatTheValue() {
        String first = service.create(new CreateApiTokenRequest("a", null), "alice").token();
        String second = service.create(new CreateApiTokenRequest("b", null), "alice").token();
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void create_whenTheUserAlreadyHasTheMaximumOfActiveTokens_isRejected() {
        when(apiTokenRepository.countByCreatedByUsernameAndExpiresAtAfter("alice", NOW_UTC))
                .thenReturn((long) ApiTokenService.MAX_ACTIVE_TOKENS_PER_USER);

        assertThatThrownBy(() -> service.create(new CreateApiTokenRequest("x", null), "alice"))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("10 tokens de API vigentes");
        verify(apiTokenRepository, never()).save(any());
    }

    @Test
    void list_aRegularUser_seesOnlyTheirOwnTokens_withoutTheirValue() {
        when(apiTokenRepository.findAllByCreatedByUsernameOrderByCreatedAtDesc("alice"))
                .thenReturn(List.of(token(alice, NOW_UTC.plusDays(10)), token(alice, NOW_UTC.minusDays(1))));

        List<ApiTokenResponse> tokens = service.list("alice", false);

        assertThat(tokens).extracting(ApiTokenResponse::ownerUsername).containsOnly("alice");
        assertThat(tokens).extracting(ApiTokenResponse::expired).containsExactly(false, true);
        verify(apiTokenRepository, never()).findAllByOrderByCreatedAtDesc();
    }

    @Test
    void list_aSecurityAdmin_seesEveryonesTokens() {
        when(apiTokenRepository.findAllByOrderByCreatedAtDesc())
                .thenReturn(List.of(token(alice, NOW_UTC.plusDays(1)), token(user("bob"), NOW_UTC.plusDays(1))));

        assertThat(service.list("admin", true)).extracting(ApiTokenResponse::ownerUsername)
                .containsExactly("alice", "bob");
    }

    @Test
    void revoke_ownToken_deletesIt() {
        ApiToken own = token(alice, NOW_UTC.plusDays(1));
        when(apiTokenRepository.findById(own.getId())).thenReturn(Optional.of(own));

        service.revoke(own.getId(), "alice", false);

        verify(apiTokenRepository).delete(own);
        verify(auditService).record(eq("API_TOKEN_REVOKED"), eq("alice"), isNull(), anyMap());
    }

    @Test
    void revoke_someoneElsesToken_looksLikeItDoesNotExist() {
        ApiToken bobs = token(user("bob"), NOW_UTC.plusDays(1));
        when(apiTokenRepository.findById(bobs.getId())).thenReturn(Optional.of(bobs));

        assertThatThrownBy(() -> service.revoke(bobs.getId(), "alice", false))
                .isInstanceOf(ResourceNotFoundException.class);
        verify(apiTokenRepository, never()).delete(any());
    }

    @Test
    void revoke_aSecurityAdmin_canRevokeAnyonesToken() {
        ApiToken bobs = token(user("bob"), NOW_UTC.plusDays(1));
        when(apiTokenRepository.findById(bobs.getId())).thenReturn(Optional.of(bobs));

        service.revoke(bobs.getId(), "admin", true);

        verify(apiTokenRepository).delete(bobs);
    }
}
