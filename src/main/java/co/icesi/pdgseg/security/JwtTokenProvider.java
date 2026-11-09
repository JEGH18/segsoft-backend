package co.icesi.pdgseg.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    public enum TokenStatus { VALID, EXPIRED, INVALID }

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token-expiration-ms}")
    private long accessTokenExpirationMs;

    @Value("${jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    /** Claim with the account's token_version when the token was issued (0 if absent). */
    static final String TOKEN_VERSION_CLAIM = "tv";

    public String generateAccessToken(String username, List<String> roles, int tokenVersion) {
        return JWT.create()
                .withSubject(username)
                .withClaim("roles", roles)
                .withClaim("type", "access")
                .withClaim(TOKEN_VERSION_CLAIM, tokenVersion)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpirationMs))
                .sign(Algorithm.HMAC256(secret));
    }

    public String generateRefreshToken(String username, int tokenVersion) {
        return JWT.create()
                .withSubject(username)
                .withClaim("type", "refresh")
                .withClaim(TOKEN_VERSION_CLAIM, tokenVersion)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenExpirationMs))
                .sign(Algorithm.HMAC256(secret));
    }

    public TokenStatus checkToken(String token) {
        try {
            buildVerifier().verify(token);
            return TokenStatus.VALID;
        } catch (TokenExpiredException e) {
            return TokenStatus.EXPIRED;
        } catch (JWTVerificationException e) {
            log.debug("JWT validation failed: {}", e.getMessage());
            return TokenStatus.INVALID;
        }
    }

    public boolean validateToken(String token) {
        return checkToken(token) == TokenStatus.VALID;
    }

    public String extractUsername(String token) {
        return decode(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return decode(token).getClaim("roles").asList(String.class);
    }

    public String extractTokenType(String token) {
        return decode(token).getClaim("type").asString();
    }

    /** Tokens issued before V36 carry no version: they count as 0, the initial one. */
    public int extractTokenVersion(String token) {
        Integer version = decode(token).getClaim(TOKEN_VERSION_CLAIM).asInt();
        return version == null ? 0 : version;
    }

    public Date extractExpiry(String token) {
        return decode(token).getExpiresAt();
    }

    private DecodedJWT decode(String token) {
        return buildVerifier().verify(token);
    }

    private JWTVerifier buildVerifier() {
        return JWT.require(Algorithm.HMAC256(secret)).build();
    }
}
