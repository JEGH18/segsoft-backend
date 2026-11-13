package co.icesi.pdgseg.security;

import co.icesi.pdgseg.exception.AccountLockedException;
import co.icesi.pdgseg.exception.AuthException;
import co.icesi.pdgseg.service.AccountAccessService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String AUTH_PATH = "/api/v1/auth/";
    private static final String CURRENT_USER_PATH = AUTH_PATH + "me";
    private static final String API_TOKENS_PATH = AUTH_PATH + "api-tokens";

    /** Granted, on top of the owner's roles, to requests authenticated with a CI/CD API token. */
    public static final String API_TOKEN_AUTHORITY = "API_TOKEN";

    private final JwtTokenProvider jwtTokenProvider;
    private final AccountAccessService accountAccessService;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, AccountAccessService accountAccessService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.accountAccessService = accountAccessService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // The traceId is already in the MDC: TraceIdFilter runs before the security chain.
        String token = resolveToken(request);
        if (ApiTokens.looksLikeApiToken(token)) {
            if (authenticateApiToken(token, request, response)) {
                filterChain.doFilter(request, response);
            }
            return;
        }
        if (token != null) {
            JwtTokenProvider.TokenStatus status = jwtTokenProvider.checkToken(token);

            if (status == JwtTokenProvider.TokenStatus.EXPIRED) {
                writeUnauthorized(response, "TOKEN_EXPIRED", "El token de acceso ha expirado");
                return;
            }

            if (status == JwtTokenProvider.TokenStatus.VALID) {
                String username = jwtTokenProvider.extractUsername(token);

                // The token alone would outlive a lock, a disabling or a deletion of its account.
                try {
                    accountAccessService.requireUsable(username, jwtTokenProvider.extractTokenVersion(token));
                } catch (AccountLockedException | AuthException e) {
                    if (isPublicAuthEndpoint(request)) {
                        // Login, logout, unlock... must still work: the request just goes on
                        // unauthenticated, as if the stale token had not been sent.
                        filterChain.doFilter(request, response);
                        return;
                    }
                    if (e instanceof AccountLockedException locked) {
                        writeError(response, 423, "ACCOUNT_LOCKED", locked.getMessage(),
                                Map.of("minutesLeft", locked.getMinutesLeft()));
                    } else {
                        writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "SESSION_REVOKED",
                                e.getMessage(), Map.of());
                    }
                    return;
                }

                List<String> roles = jwtTokenProvider.extractRoles(token);

                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .toList();

                UserDetails principal = User.withUsername(username)
                        .password("")
                        .authorities(authorities)
                        .build();

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(principal, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * CI/CD API token ("pdgseg_..."): authenticates as the token's owner, with the owner's roles plus
     * the {@link #API_TOKEN_AUTHORITY} authority. It cannot manage API tokens, so a leaked token cannot
     * mint new ones.
     *
     * @return whether the request should go on down the chain; when false the response is written
     */
    private boolean authenticateApiToken(String token, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (path.startsWith(API_TOKENS_PATH)) {
            writeError(response, HttpServletResponse.SC_FORBIDDEN, "API_TOKEN_NOT_ALLOWED",
                    "Los tokens de API no sirven para gestionar tokens de API. Inicia sesión en la aplicación.",
                    Map.of());
            return false;
        }
        if (isPublicAuthEndpoint(request)) {
            // Login, logout, unlock... need no credential: the request goes on unauthenticated.
            return true;
        }

        AccountAccessService.ApiTokenIdentity identity;
        try {
            identity = accountAccessService.authenticateApiToken(token);
        } catch (AccountLockedException locked) {
            writeError(response, 423, "ACCOUNT_LOCKED", locked.getMessage(),
                    Map.of("minutesLeft", locked.getMinutesLeft()));
            return false;
        } catch (AuthException e) {
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "INVALID_API_TOKEN", e.getMessage(), Map.of());
            return false;
        }

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        identity.roles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        authorities.add(new SimpleGrantedAuthority(API_TOKEN_AUTHORITY));

        UserDetails principal = User.withUsername(identity.username())
                .password("")
                .authorities(authorities)
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null, authorities));
        return true;
    }

    private void writeUnauthorized(HttpServletResponse response, String errorCode, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"errorCode\":\"" + errorCode + "\",\"message\":\"" + message + "\"}");
    }

    /** The endpoints under /api/v1/auth that do not need a session; /me does. */
    private static boolean isPublicAuthEndpoint(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith(AUTH_PATH) && !path.equals(CURRENT_USER_PATH);
    }

    private void writeError(HttpServletResponse response, int status, String errorCode, String message,
                            Map<String, Object> extra) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("errorCode", errorCode);
        body.put("message", message);
        body.putAll(extra);
        body.put("traceId", MDC.get("traceId"));
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        JSON.writeValue(response.getWriter(), body);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
}
