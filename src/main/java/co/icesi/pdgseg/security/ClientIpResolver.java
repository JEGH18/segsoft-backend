package co.icesi.pdgseg.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.regex.Pattern;

/**
 * The IP of the person behind a request, for the audit log and the per-IP limits.
 *
 * <p>In production a request goes browser → Vercel (rewrite of /api) → Caddy → backend. Caddy
 * replaces X-Forwarded-For with the address it sees, which is Vercel's, the same for many users.
 * The Vercel middleware therefore sends the real IP in {@value #CLIENT_IP_HEADER}, together with
 * a secret shared only with this server: without the secret the header is ignored, so someone
 * who calls the server directly cannot choose the IP that gets recorded or limited.
 */
@Component
public class ClientIpResolver {

    public static final String CLIENT_IP_HEADER = "X-SegSoft-Client-IP";
    public static final String PROXY_SECRET_HEADER = "X-SegSoft-Proxy-Secret";

    /** IPv4 or IPv6 text that fits in auth_audit_log.ip_address (VARCHAR(45)). */
    private static final Pattern IP = Pattern.compile("[0-9A-Fa-f:.]{2,45}");

    private final byte[] proxySecret;

    public ClientIpResolver(@Value("${app.trusted-proxy-secret:}") String proxySecret) {
        this.proxySecret = proxySecret.trim().getBytes(StandardCharsets.UTF_8);
    }

    public String resolve(HttpServletRequest request) {
        String fromProxy = request.getHeader(CLIENT_IP_HEADER);
        if (fromTrustedProxy(request) && fromProxy != null && IP.matcher(fromProxy.trim()).matches()) {
            return fromProxy.trim();
        }
        // Set by Caddy, which discards whatever the caller sent in it.
        String forwarded = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwarded)) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private boolean fromTrustedProxy(HttpServletRequest request) {
        String sent = request.getHeader(PROXY_SECRET_HEADER);
        return proxySecret.length > 0 && sent != null
                && MessageDigest.isEqual(proxySecret, sent.trim().getBytes(StandardCharsets.UTF_8));
    }
}
