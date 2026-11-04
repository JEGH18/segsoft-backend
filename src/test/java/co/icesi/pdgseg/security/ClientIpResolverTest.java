package co.icesi.pdgseg.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    private static final String SECRET = "secreto-compartido-con-vercel";

    /** A request as it reaches the backend: Caddy put the address it saw (Vercel's) in X-Forwarded-For. */
    private static MockHttpServletRequest throughCaddy() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("172.18.0.5");
        request.addHeader("X-Forwarded-For", "3.88.216.244");
        return request;
    }

    @Test
    void withTheSecret_usesTheIpSentByTheVercelMiddleware() {
        MockHttpServletRequest request = throughCaddy();
        request.addHeader(ClientIpResolver.PROXY_SECRET_HEADER, SECRET);
        request.addHeader(ClientIpResolver.CLIENT_IP_HEADER, " 181.53.12.7 ");

        assertThat(new ClientIpResolver(SECRET).resolve(request)).isEqualTo("181.53.12.7");
    }

    @Test
    void acceptsIpv6() {
        MockHttpServletRequest request = throughCaddy();
        request.addHeader(ClientIpResolver.PROXY_SECRET_HEADER, SECRET);
        request.addHeader(ClientIpResolver.CLIENT_IP_HEADER, "2800:e2:2b80:1a3::5");

        assertThat(new ClientIpResolver(SECRET).resolve(request)).isEqualTo("2800:e2:2b80:1a3::5");
    }

    @Test
    void withoutTheRightSecret_theClaimedIpIsIgnored() {
        MockHttpServletRequest wrongSecret = throughCaddy();
        wrongSecret.addHeader(ClientIpResolver.PROXY_SECRET_HEADER, "adivinado");
        wrongSecret.addHeader(ClientIpResolver.CLIENT_IP_HEADER, "1.2.3.4");
        MockHttpServletRequest noSecret = throughCaddy();
        noSecret.addHeader(ClientIpResolver.CLIENT_IP_HEADER, "1.2.3.4");

        ClientIpResolver resolver = new ClientIpResolver(SECRET);
        assertThat(resolver.resolve(wrongSecret)).isEqualTo("3.88.216.244");
        assertThat(resolver.resolve(noSecret)).isEqualTo("3.88.216.244");
    }

    @Test
    void whenNoSecretIsConfigured_noHeaderIsTrusted_evenAnEmptySecret() {
        MockHttpServletRequest request = throughCaddy();
        request.addHeader(ClientIpResolver.PROXY_SECRET_HEADER, "");
        request.addHeader(ClientIpResolver.CLIENT_IP_HEADER, "1.2.3.4");

        assertThat(new ClientIpResolver("").resolve(request)).isEqualTo("3.88.216.244");
    }

    @Test
    void somethingThatIsNotAnIp_isIgnored() {
        MockHttpServletRequest request = throughCaddy();
        request.addHeader(ClientIpResolver.PROXY_SECRET_HEADER, SECRET);
        request.addHeader(ClientIpResolver.CLIENT_IP_HEADER, "1.2.3.4'; DROP TABLE users;--");

        assertThat(new ClientIpResolver(SECRET).resolve(request)).isEqualTo("3.88.216.244");
    }

    @Test
    void withoutAnyProxy_usesTheSocketAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");

        assertThat(new ClientIpResolver(SECRET).resolve(request)).isEqualTo("127.0.0.1");
    }
}
