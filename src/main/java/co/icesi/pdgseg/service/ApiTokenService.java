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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Long-lived credentials for CI/CD pipelines, separate from the short-lived web session JWT.
 * Each token belongs to the user who created it and authenticates as that user (see
 * {@link AccountAccessService#authenticateApiToken}). Only a SHA-256 hash is ever persisted; the
 * plaintext value is generated, returned once, and then unrecoverable -- same principle as a password.
 */
@Service
public class ApiTokenService {

    /** Unexpired tokens one user may hold at a time. */
    static final int MAX_ACTIVE_TOKENS_PER_USER = 10;

    private final ApiTokenRepository apiTokenRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;
    private final Clock clock;

    @Autowired
    public ApiTokenService(ApiTokenRepository apiTokenRepository, UserRepository userRepository,
                           AuditService auditService) {
        this(apiTokenRepository, userRepository, auditService, Clock.systemUTC());
    }

    ApiTokenService(ApiTokenRepository apiTokenRepository, UserRepository userRepository,
                    AuditService auditService, Clock clock) {
        this.apiTokenRepository = apiTokenRepository;
        this.userRepository = userRepository;
        this.auditService = auditService;
        this.clock = clock;
    }

    @Transactional
    public CreateApiTokenResponse create(CreateApiTokenRequest request, String username) {
        User owner = userRepository.findByUsername(username).orElseThrow(
            () -> new IllegalStateException("Usuario autenticado no encontrado: " + username));

        OffsetDateTime now = OffsetDateTime.now(clock);
        if (apiTokenRepository.countByCreatedByUsernameAndExpiresAtAfter(username, now) >= MAX_ACTIVE_TOKENS_PER_USER) {
            throw new ConflictException("Ya tienes " + MAX_ACTIVE_TOKENS_PER_USER
                + " tokens de API vigentes. Revoca alguno que no uses antes de crear otro.");
        }

        String plaintext = ApiTokens.generate();

        ApiToken token = new ApiToken();
        token.setName(request.name().trim());
        token.setTokenHash(ApiTokens.hash(plaintext));
        token.setTokenPrefix(ApiTokens.displayPrefix(plaintext));
        token.setCreatedBy(owner);
        token.setExpiresAt(now.plusDays(request.expiresInDaysOrDefault()));

        ApiToken saved = apiTokenRepository.save(token);
        auditService.record("API_TOKEN_CREATED", username, null,
            Map.of("tokenId", saved.getId().toString(), "expiresAt", saved.getExpiresAt().toString()));

        return new CreateApiTokenResponse(saved.getId(), saved.getName(), plaintext, saved.getTokenPrefix(),
            saved.getCreatedAt(), saved.getExpiresAt());
    }

    /** The caller's own tokens; a SECURITY_ADMIN gets everyone's. */
    @Transactional(readOnly = true)
    public List<ApiTokenResponse> list(String username, boolean securityAdmin) {
        List<ApiToken> tokens = securityAdmin
            ? apiTokenRepository.findAllByOrderByCreatedAtDesc()
            : apiTokenRepository.findAllByCreatedByUsernameOrderByCreatedAtDesc(username);
        OffsetDateTime now = OffsetDateTime.now(clock);
        return tokens.stream().map(t -> toResponse(t, now)).toList();
    }

    /**
     * Deletes the token, so any pipeline using it stops authenticating at once. A token of another
     * user is reported as not found (unless the caller is a SECURITY_ADMIN), so ids cannot be probed.
     */
    @Transactional
    public void revoke(UUID id, String username, boolean securityAdmin) {
        ApiToken token = apiTokenRepository.findById(id)
            .filter(t -> securityAdmin || t.getCreatedBy().getUsername().equals(username))
            .orElseThrow(() -> new ResourceNotFoundException("Token no encontrado con id: " + id));
        apiTokenRepository.delete(token);
        auditService.record("API_TOKEN_REVOKED", username, null,
            Map.of("tokenId", id.toString(), "owner", token.getCreatedBy().getUsername()));
    }

    private static ApiTokenResponse toResponse(ApiToken t, OffsetDateTime now) {
        return new ApiTokenResponse(t.getId(), t.getName(), t.getTokenPrefix(), t.getCreatedBy().getUsername(),
            t.getCreatedAt(), t.getExpiresAt(), t.getLastUsedAt(), t.isExpired(now));
    }
}
