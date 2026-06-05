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

    public String generateAccessToken(String username, List<String> roles) {
        return JWT.create()
                .withSubject(username)
                .withClaim("roles", roles)
                .withClaim("type", "access")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpirationMs))
                .sign(Algorithm.HMAC256(secret));
    }

    public String generateRefreshToken(String username) {
        return JWT.create()
                .withSubject(username)
                .withClaim("type", "refresh")
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
