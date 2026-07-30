package systems.hugmesh.adminbff.config;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Dev/test-profile counterpart to {@link SecurityConfigPathRulesTest}: with the
 * {@code dev} profile active the {@code devFilterChain} loads, so the springdoc
 * OpenAPI spec path is PUBLIC (so {@code gen:fetch} / the docs pipeline can curl
 * {@code /v3/api-docs} locally without a Casdoor token) — while every other gated
 * route (here {@code /bff/admin/**}) keeps its prod policy. This proves the
 * profile split only loosens the spec paths and nothing else.
 */
@WebFluxTest(controllers = Probes.class)
@Import({SecurityConfig.class, systems.hugmesh.commons.security.DomainRegistry.class})
@ActiveProfiles("dev")
class SecurityConfigDevSpecPublicTest {

    @Autowired ApplicationContext context;

    WebTestClient client;

    @BeforeEach
    void setUpWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Test
    void apiDocs_isPublic_inDev() {
        client.get().uri("/v3/api-docs").exchange().expectStatus().isOk();
    }

    @Test
    void admin_stillRequiresAdmin_inDev() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/admin/allowlist").exchange().expectStatus().isForbidden();
    }

    @Test
    void admin_allowedForAdmin_inDev() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_ADMIN")))
                .get().uri("/bff/admin/allowlist").exchange().expectStatus().isOk();
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }
}
