package co.icesi.pdgseg.service;

import co.icesi.pdgseg.dto.request.CreateApiTokenRequest;
import co.icesi.pdgseg.dto.response.ApiTokenResponse;
import co.icesi.pdgseg.dto.response.CreateApiTokenResponse;
import co.icesi.pdgseg.entity.ApiToken;
import co.icesi.pdgseg.entity.User;
import co.icesi.pdgseg.exception.ResourceNotFoundException;
import co.icesi.pdgseg.repository.ApiTokenRepository;
import co.icesi.pdgseg.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Long-lived credentials for CI/CD pipelines, separate from the short-lived
 * web session JWT. Only a SHA-256 hash is ever persisted; the plaintext value
 * is generated, returned once, and then unrecoverable -- same principle as a
 * password.
 */
@Service
public class ApiTokenService {

    private static final String TOKEN_PREFIX = "pdgseg_";
    private static final int TOKEN_RANDOM_BYTES = 32;

    private final ApiTokenRepository apiTokenRepository;
    private final UserRepository userRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public ApiTokenService(ApiTokenRepository apiTokenRepository, UserRepository userRepository) {
        this.apiTokenRepository = apiTokenRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public CreateApiTokenResponse create(CreateApiTokenRequest request, String username) {
        User creator = userRepository.findByUsername(username).orElseThrow(
            () -> new IllegalStateException("Usuario autenticado no encontrado: " + username));

        String plaintext = generateToken();

        ApiToken token = new ApiToken();
        token.setName(request.name());
        token.setTokenHash(sha256(plaintext));
        token.setCreatedBy(creator);

        ApiToken saved = apiTokenRepository.save(token);

        return new CreateApiTokenResponse(saved.getId(), saved.getName(), plaintext, saved.getCreatedAt());
    }

    @Transactional(readOnly = true)
    public List<ApiTokenResponse> list() {
        return apiTokenRepository.findAllByOrderByCreatedAtDesc().stream()
            .map(t -> new ApiTokenResponse(
                t.getId(),
                t.getName(),
                t.getCreatedAt(),
                t.getCreatedBy() != null ? t.getCreatedBy().getId() : null))
            .toList();
    }

    @Transactional
    public void revoke(UUID id) {
        if (!apiTokenRepository.existsById(id)) {
            throw new ResourceNotFoundException("Token no encontrado con id: " + id);
        }
        apiTokenRepository.deleteById(id);
    }

    private String generateToken() {
        byte[] randomBytes = new byte[TOKEN_RANDOM_BYTES];
        secureRandom.nextBytes(randomBytes);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }
}
