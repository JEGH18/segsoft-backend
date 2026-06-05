package co.icesi.pdgseg.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderTest {

    private JwtTokenProvider provider;

    @BeforeEach
    void setUp() {
        provider = new JwtTokenProvider();
        ReflectionTestUtils.setField(provider, "secret", "test-secret-for-unit-tests-minimum-32-chars!!");
        ReflectionTestUtils.setField(provider, "accessTokenExpirationMs", 900_000L);
        ReflectionTestUtils.setField(provider, "refreshTokenExpirationMs", 28_800_000L);
    }

    @Test
    void generateAccessToken_returnsNonBlankToken() {
        String token = provider.generateAccessToken("alice", List.of("DEVELOPER"));
        assertThat(token).isNotBlank();
    }

    @Test
    void validateToken_returnsTrueForFreshToken() {
        String token = provider.generateAccessToken("alice", List.of("DEVELOPER"));
        assertThat(provider.validateToken(token)).isTrue();
    }

    @Test
    void validateToken_returnsFalseForTamperedSignature() {
        String token = provider.generateAccessToken("alice", List.of("DEVELOPER"));
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "invalidsig";
        assertThat(provider.validateToken(tampered)).isFalse();
    }

    @Test
    void validateToken_returnsFalseForExpiredToken() {
        JwtTokenProvider expiredProvider = new JwtTokenProvider();
        ReflectionTestUtils.setField(expiredProvider, "secret",
                "test-secret-for-unit-tests-minimum-32-chars!!");
        ReflectionTestUtils.setField(expiredProvider, "accessTokenExpirationMs", -1L);
        ReflectionTestUtils.setField(expiredProvider, "refreshTokenExpirationMs", 28_800_000L);

        String token = expiredProvider.generateAccessToken("alice", List.of("DEVELOPER"));
        assertThat(provider.validateToken(token)).isFalse();
        assertThat(provider.checkToken(token)).isEqualTo(JwtTokenProvider.TokenStatus.EXPIRED);
    }

    @Test
    void validateToken_returnsFalseForAlgorithmNone() {
        String header  = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"hacker\",\"exp\":9999999999}".getBytes(StandardCharsets.UTF_8));
        String noneToken = header + "." + payload + ".";

        assertThat(provider.validateToken(noneToken)).isFalse();
    }

    @Test
    void extractUsername_returnsCorrectSubject() {
        String token = provider.generateAccessToken("bob", List.of("AUDITOR"));
        assertThat(provider.extractUsername(token)).isEqualTo("bob");
    }

    @Test
    void extractRoles_returnsCorrectList() {
        List<String> roles = List.of("DEVELOPER", "AUDITOR");
        String token = provider.generateAccessToken("carol", roles);
        assertThat(provider.extractRoles(token)).containsExactlyInAnyOrderElementsOf(roles);
    }

    @Test
    void extractTokenType_returnsAccessForAccessToken() {
        String token = provider.generateAccessToken("alice", List.of("DEVELOPER"));
        assertThat(provider.extractTokenType(token)).isEqualTo("access");
    }

    @Test
    void extractTokenType_returnsRefreshForRefreshToken() {
        String token = provider.generateRefreshToken("alice");
        assertThat(provider.extractTokenType(token)).isEqualTo("refresh");
    }

    @Test
    void refreshToken_cannotBeUsedAsAccessToken() {
        // A refreshToken should NOT set authentication context because the filter
        // checks type == "access". We verify type claim is "refresh".
        String token = provider.generateRefreshToken("alice");
        assertThat(provider.extractTokenType(token)).isNotEqualTo("access");
    }
}
