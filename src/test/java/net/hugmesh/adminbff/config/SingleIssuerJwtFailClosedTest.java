package net.hugmesh.adminbff.config;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.data.r2dbc.autoconfigure.DataR2dbcAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.liquibase.autoconfigure.LiquibaseAutoConfiguration;
import org.springframework.boot.r2dbc.autoconfigure.R2dbcAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.testsupport.TestIssuer;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fail-closed coverage for the admin BFF's SINGLE-ISSUER (back-compat) resource-server
 * path — the {@code o.jwt(j -&gt; j.jwtAuthenticationConverter(...))} branch in
 * {@link SecurityConfig#resourceServer} that EVERY single-brand cluster runs and that the
 * planned D6 cookie / D8 MFA opaque-session-bridge changes will ride.
 *
 * <p><b>Why this fills a real gap.</b> The repo already proves fail-closed on the OPT-IN
 * multi-issuer resolver path ({@link MultiIssuerSecuritySliceTest}) and the path/role
 * policy with a MOCKED decoder ({@link SecurityConfigPathRulesTest},
 * {@code @MockitoBean ReactiveJwtDecoder}). NEITHER exercises the DEFAULT single-issuer
 * {@code o.jwt(...)} decoder with a REAL signature- and issuer-validating
 * {@link ReactiveJwtDecoder} against a live {@link WebTestClient} — so the single-issuer
 * 401 fail-closed behaviour (the production default) was UNTESTED at the HTTP layer. This
 * test closes that gap.
 *
 * <p>Drives a real {@code @SpringBootTest} reactive web context wired with ONLY the
 * production {@link SecurityConfig} + {@link DomainRegistry} + a real
 * {@link NimbusReactiveJwtDecoder} built EXACTLY as Spring Boot's resource-server
 * autoconfig builds the single-issuer decoder: {@code withJwkSetUri(...)} + the
 * {@code createDefaultWithIssuer(issuer)} validator (exp/nbf + an {@code iss}-binding
 * check). The JWKS is served by an in-process {@link TestIssuer} on {@code 127.0.0.1}, so
 * RS256 tokens are validated with NO network and NO live Casdoor. Because no
 * {@code app.tenancy.issuers} is configured, {@link DomainRegistry#isMultiIssuer()} is
 * false and {@code resourceServer(...)} takes the single-issuer {@code o.jwt(...)} branch
 * — exactly the production default.
 *
 * <p>Categories (per the comprehensive test standard — ALLOW vs DENY isolation):
 * <ol>
 *   <li><b>(a) ALLOW</b> — a token from the configured (valid) issuer for this brand is
 *       ACCEPTED (200) and the Casdoor converter ran (ROLE_ floor + roles + the
 *       iss-derived {@code DOMAIN_default});</li>
 *   <li><b>(b) DENY</b> — a perfectly well-formed, correctly-signed token from a
 *       FOREIGN / unconfigured issuer is REJECTED with 401, fail-closed: never silently
 *       accepted, never treated as anonymous-allowed on an {@code authenticated()}
 *       surface;</li>
 *   <li><b>(c) DENY</b> — a tampered-signature token AND a wrong-{@code kid} / unknown
 *       signing-key token (both claiming the trusted issuer) are REJECTED with 401.</li>
 * </ol>
 *
 * <p>The DENY assertions are MUTATION-RESISTANT: weaken the decoder to skip signature or
 * issuer validation (or default-accept an unknown token) and (b)/(c) flip green-to-200.
 * The probe path {@code /whoami} falls to {@code anyExchange().authenticated()}, isolating
 * "did the token authenticate at all" from the coarser role gates.
 */
@SpringBootTest(
        classes = SingleIssuerJwtFailClosedTest.SingleIssuerSecurityTestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class SingleIssuerJwtFailClosedTest {

    @Autowired WebTestClient client;
    @Autowired TestIssuer trustedIssuer;

    private TestIssuer foreignIssuer() {
        return SingleIssuerSecurityTestApp.FOREIGN;
    }

    /** Close the static, never-Spring-managed FOREIGN issuer's in-process server (the
     *  Spring-managed {@code trustedIssuer} bean is auto-closed at context shutdown via
     *  {@link TestIssuer}'s {@link AutoCloseable}). */
    @AfterAll
    static void stopForeignIssuer() {
        SingleIssuerSecurityTestApp.FOREIGN.close();
    }

    // ── (a) ALLOW: valid configured-issuer token is accepted ──────────────────

    @Test
    void userSituational_validConfiguredIssuerToken_isAccepted_andConverterRan() {
        String token = trustedIssuer.mint("admin-user", List.of("admin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("a token from the configured single issuer authenticates and the "
                                + "Casdoor converter runs (ROLE_ floor + roles + iss-derived DOMAIN_default)")
                        .contains("ROLE_USER")
                        .contains("ROLE_ADMIN")
                        // single-issuer back-compat: the lone configured issuer maps to DOMAIN_default
                        .contains("DOMAIN_default"));
    }

    // ── (b) DENY: foreign / unconfigured issuer -> 401 fail-closed ────────────

    @Test
    void crossUser_foreignIssuerToken_is401_failClosed_neverSilentlyAccepted() {
        // A perfectly well-formed, correctly-signed JWT from an issuer that is NOT the
        // configured spring.security.oauth2.resourceserver.jwt.issuer-uri. The
        // createDefaultWithIssuer validator binds the decoder to the trusted iss, so this
        // token's foreign iss fails validation -> 401. There is NO default-accept and the
        // token is NOT treated as anonymous-allowed on an authenticated() surface.
        String token = foreignIssuer().mint("attacker", List.of("admin", "superadmin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_foreignIssuerToken_signedByForeignKey_alsoFailsJwksResolution_401() {
        // Even ignoring the iss check, the foreign issuer's signing key is NOT in the
        // trusted issuer's published JWKS, so signature resolution against the configured
        // jwk-set-uri also fails -> 401. Belt-and-suspenders fail-closed.
        String token = foreignIssuer().mintWithClaims("attacker", Map.of(
                "iss", SingleIssuerSecurityTestApp.FOREIGN.issuerUri(),
                "roles", List.of(Map.of("name", "superadmin"))));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void noBearer_onAuthenticatedSurface_is401_notAnonymousAllowed() {
        client.get().uri("/whoami")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void garbageBearer_is401() {
        client.get().uri("/whoami")
                .header("Authorization", "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (c) DENY: tampered signature / wrong-kid -> 401 ───────────────────────

    @Test
    void crossUser_tamperedSignature_is401() {
        // A trusted-issuer token whose signature bytes are corrupted fails RS256
        // verification against the published JWKS -> 401 (never silently accepted).
        String token = trustedIssuer.mint("admin-user", List.of("admin"));
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + tampered)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_wrongKidUnknownSigningKey_is401() {
        // A token claiming the TRUSTED issuer's iss but signed by a fresh, UNPUBLISHED key
        // carrying an unknown kid. The decoder fetches the trusted issuer's JWKS, finds no
        // key for that kid, cannot verify the signature -> 401. An attacker who controls a
        // keypair the issuer never published cannot mint an accepted token.
        String token = trustedIssuer.mintWithForeignKey("attacker", List.of("admin", "superadmin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /**
     * Minimal reactive web context for the single-issuer resource-server path. Imports the
     * PRODUCTION {@link SecurityConfig} + {@link DomainRegistry} and contributes a real
     * single-issuer {@link ReactiveJwtDecoder} (the bean the production {@code o.jwt(...)}
     * branch resolves from context) built EXACTLY as Boot's autoconfig builds it. Pulls in
     * NO database / Liquibase / scheduling — this is a focused security context.
     *
     * <p>The lone trusted issuer is the in-process {@link TestIssuer}; with no
     * {@code app.tenancy.issuers} the {@link DomainRegistry} is single-issuer
     * ({@code isMultiIssuer()} false) so {@code SecurityConfig.resourceServer} takes the
     * {@code o.jwt(...)} branch under test.
     */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration(exclude = {
            DataSourceAutoConfiguration.class,
            R2dbcAutoConfiguration.class,
            DataR2dbcAutoConfiguration.class,
            LiquibaseAutoConfiguration.class
    })
    @Import({SecurityConfig.class, AuthoritiesProbeController.class})
    static class SingleIssuerSecurityTestApp {

        /** A SECOND in-process issuer that is NEVER configured/trusted — the source of the
         *  foreign-issuer DENY tokens. Static so the test class can mint from it. */
        static final TestIssuer FOREIGN = new TestIssuer();

        /** The lone trusted issuer (the back-compat single issuer). */
        @Bean
        TestIssuer trustedIssuer() {
            return new TestIssuer();
        }

        /** Single-issuer registry: ONLY the trusted issuer, NO app.tenancy.issuers, so the
         *  registry is single-issuer (isMultiIssuer() == false) and every token maps to
         *  DOMAIN_default — the production single-brand default. */
        @Bean
        DomainRegistry domainRegistry(TestIssuer trustedIssuer) {
            DomainRegistry registry = new DomainRegistry(trustedIssuer.issuerUri(), "");
            assertThat(registry.isMultiIssuer())
                    .as("single configured issuer + no app.tenancy.issuers => single-issuer mode, "
                            + "so SecurityConfig.resourceServer takes the o.jwt(...) branch under test")
                    .isFalse();
            return registry;
        }

        /** The single-issuer decoder the {@code o.jwt(...)} branch resolves from context —
         *  built byte-for-byte like Boot's resource-server autoconfig for the configured
         *  {@code issuer-uri} + {@code jwk-set-uri}: a JWKS decoder plus the
         *  {@code createDefaultWithIssuer} validator (exp/nbf + iss-binding). The
         *  iss-binding is what fail-closes a foreign-issuer token. */
        @Bean
        ReactiveJwtDecoder reactiveJwtDecoder(TestIssuer trustedIssuer) {
            NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                    .withJwkSetUri(trustedIssuer.issuerUri() + "/.well-known/jwks.json")
                    .build();
            OAuth2TokenValidator<Jwt> withIssuer =
                    JwtValidators.createDefaultWithIssuer(trustedIssuer.issuerUri());
            decoder.setJwtValidator(withIssuer);
            return decoder;
        }
    }

    /** Probe controller: echoes the authenticated principal's authorities. {@code /whoami}
     *  is an ungoverned path that falls to {@code anyExchange().authenticated()} — the
     *  cleanest "did the token authenticate, and as what" probe, isolated from role gates. */
    @RestController
    static class AuthoritiesProbeController {
        @GetMapping("/whoami")
        Mono<String> whoami() {
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                            .map(Object::toString)
                            .collect(Collectors.joining(",")))
                    .defaultIfEmpty("ANONYMOUS");
        }
    }
}
