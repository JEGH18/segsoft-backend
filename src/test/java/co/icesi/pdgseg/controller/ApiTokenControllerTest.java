package co.icesi.pdgseg.controller;

import co.icesi.pdgseg.config.SecurityConfig;
import co.icesi.pdgseg.dto.request.CreateApiTokenRequest;
import co.icesi.pdgseg.dto.response.CreateApiTokenResponse;
import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.security.ClientIpResolver;
import co.icesi.pdgseg.security.JwtTokenProvider;
import co.icesi.pdgseg.security.UserDetailsServiceImpl;
import co.icesi.pdgseg.service.AccountAccessService;
import co.icesi.pdgseg.service.ApiTokenService;
import co.icesi.pdgseg.service.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** /api/v1/auth/api-tokens, and authentication with "Authorization: Bearer pdgseg_..." through the real filter. */
@WebMvcTest(controllers = {ApiTokenController.class, ApiTokenControllerTest.WhoAmIController.class})
@Import({SecurityConfig.class, ClientIpResolver.class, ApiTokenControllerTest.WhoAmIController.class})
class ApiTokenControllerTest {

    /** Stands in for any protected endpoint: tells who the request was authenticated as. */
    @RestController
    static class WhoAmIController {
        @GetMapping("/api/v1/test/whoami")
        Map<String, Object> whoami(Authentication authentication) {
            return Map.of("username", authentication.getName(),
                    "authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList());
        }
    }

    private static final String API_TOKEN = "pdgseg_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    @Autowired MockMvc mockMvc;

    @MockBean ApiTokenService apiTokenService;
    @MockBean JwtTokenProvider jwtTokenProvider;
    @MockBean AccountAccessService accountAccessService;
    @MockBean UserDetailsServiceImpl userDetailsService;
    @MockBean AuditService auditService;

    // --- authenticating with an API token ---

    @Test
    void aValidApiToken_authenticatesAsItsOwner_withTheOwnersRolesAndTheApiTokenAuthority() throws Exception {
        when(accountAccessService.authenticateApiToken(API_TOKEN))
                .thenReturn(new AccountAccessService.ApiTokenIdentity("ci-bot", List.of("DEVELOPER")));

        mockMvc.perform(get("/api/v1/test/whoami").header("Authorization", "Bearer " + API_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("ci-bot"))
                .andExpect(jsonPath("$.authorities[0]").value("API_TOKEN"))
                .andExpect(jsonPath("$.authorities[1]").value("ROLE_DEVELOPER"));
        verify(jwtTokenProvider, never()).checkToken(anyString());
    }

    @Test
    void anInvalidApiToken_isRejectedWith401AndAClearMessage() throws Exception {
        when(accountAccessService.authenticateApiToken(API_TOKEN))
                .thenThrow(new AuthException("El token de API no es válido, venció o fue revocado."));

        mockMvc.perform(get("/api/v1/test/whoami").header("Authorization", "Bearer " + API_TOKEN))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_API_TOKEN"))
                .andExpect(jsonPath("$.message").value("El token de API no es válido, venció o fue revocado."));
    }

    @Test
    void anApiTokenOfALockedAccount_isRejectedWith423() throws Exception {
        when(accountAccessService.authenticateApiToken(API_TOKEN))
                .thenThrow(new AccountLockedException("Cuenta bloqueada", 5));

        mockMvc.perform(get("/api/v1/test/whoami").header("Authorization", "Bearer " + API_TOKEN))
                .andExpect(status().is(423))
                .andExpect(jsonPath("$.errorCode").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.minutesLeft").value(5));
    }

    @Test
    void anApiToken_cannotManageApiTokens() throws Exception {
        mockMvc.perform(post("/api/v1/auth/api-tokens").header("Authorization", "Bearer " + API_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"otro\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("API_TOKEN_NOT_ALLOWED"));
        mockMvc.perform(get("/api/v1/auth/api-tokens").header("Authorization", "Bearer " + API_TOKEN))
                .andExpect(status().isForbidden());

        verify(accountAccessService, never()).authenticateApiToken(anyString());
        verifyNoInteractions(apiTokenService);
    }

    @Test
    void withoutCredentials_aProtectedEndpointIs401() throws Exception {
        mockMvc.perform(get("/api/v1/test/whoami")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/auth/api-tokens")).andExpect(status().isUnauthorized());
    }

    // --- managing tokens with a web session ---

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void create_asDeveloper_returns201WithThePlaintextOnce() throws Exception {
        UUID id = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.parse("2026-11-09T12:00:00Z");
        when(apiTokenService.create(any(CreateApiTokenRequest.class), eq("dev"))).thenReturn(
                new CreateApiTokenResponse(id, "GitHub Actions", API_TOKEN, "pdgseg_abcde", now, now.plusDays(90)));

        mockMvc.perform(post("/api/v1/auth/api-tokens")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"GitHub Actions\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").value(API_TOKEN))
                .andExpect(jsonPath("$.tokenPrefix").value("pdgseg_abcde"));
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void create_withAnExpiryOutOfRange_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/api-tokens")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\",\"expiresInDays\":400}"))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(apiTokenService);
    }

    @Test
    @WithMockUser(username = "dev", roles = "DEVELOPER")
    void list_asDeveloper_asksOnlyForTheirOwnTokens() throws Exception {
        when(apiTokenService.list("dev", false)).thenReturn(List.of());
        mockMvc.perform(get("/api/v1/auth/api-tokens")).andExpect(status().isOk());
        verify(apiTokenService).list("dev", false);
    }

    @Test
    @WithMockUser(username = "admin", roles = "SECURITY_ADMIN")
    void listAndRevoke_asSecurityAdmin_coverEveryonesTokens() throws Exception {
        UUID id = UUID.randomUUID();
        when(apiTokenService.list("admin", true)).thenReturn(List.of());

        mockMvc.perform(get("/api/v1/auth/api-tokens")).andExpect(status().isOk());
        mockMvc.perform(delete("/api/v1/auth/api-tokens/{id}", id)).andExpect(status().isNoContent());

        verify(apiTokenService).list("admin", true);
        verify(apiTokenService).revoke(id, "admin", true);
    }
}
