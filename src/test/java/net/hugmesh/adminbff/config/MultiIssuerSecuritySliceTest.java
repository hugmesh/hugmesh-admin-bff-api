package net.hugmesh.adminbff.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.testsupport.TestIssuer;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Multi-issuer security-slice for hugmesh-admin-bff-api — the 10th resource-server
 * repo to carry the org-wide pattern proven first in hugmesh-gateway and replicated
 * in hugmesh-actions. Completes the cross-repo D2 multi-issuer slice coverage.
 *
 * <p>Drives a {@link WebTestClient} against the REAL {@link SecurityConfig#filterChain}
 * wired with the REAL {@link TenancyResourceServerConfig#tenantAuthManagerResolver()}
 * (multi-issuer ENABLED). Each brand is backed by a {@link TestIssuer} — an in-process
 * JWKS + OIDC-discovery server on {@code 127.0.0.1} — so {@code fromIssuerLocation}
 * validates real RS256-signed tokens with NO network and NO live Casdoor.
 *
 * <p>The keystones (categories per the comprehensive test standard):
 * <ol>
 *   <li><b>(a) trusted issuer resolves + DOMAIN_&lt;x&gt; authority emitted</b>
 *       (USER-SITUATIONAL): a brand-X token resolves to brand-X's manager,
 *       authenticates, and {@code DOMAIN_brandx} is stamped from the validated iss
 *       (never the other brand);</li>
 *   <li><b>(b) UNKNOWN/untrusted issuer -&gt; 401 fail-closed</b> (CROSS-USER DENY): a
 *       perfectly well-formed, correctly-signed token from an issuer NOT in
 *       {@code app.tenancy.issuers} gets NO manager and 401s, NEVER a default-accept;</li>
 *   <li><b>(c) signature mismatch / cross-brand isolation -&gt; 401</b> (CROSS-USER
 *       DENY): a token whose payload claims brand-Y's iss but is signed by brand-X's
 *       key fails brand-Y's JWKS validation -&gt; 401; a tampered signature -&gt; 401;</li>
 *   <li><b>(d) reserved-authority forge defense</b> (CROSS-USER DENY): a token whose
 *       {@code permissions} claim tries to inject {@code DOMAIN_}/{@code ROLE_}/{@code MFA_}
 *       authorities is stripped by the CasdoorAuthorities reserved-prefix filter — the
 *       ONLY {@code DOMAIN_} authority is the cryptographically-validated iss.</li>
 * </ol>
 *
 * <p>DENY assertions are MUTATION-RESISTANT: (b)/(c) assert HTTP 401 driven by the real
 * resolver fail-closed (remove the {@code isTrusted} guard / default-accept and they
 * flip green-to-403/200); (d) asserts the forged authorities are ABSENT from the live
 * authority set (delete the reserved-prefix filter and {@code DOMAIN_brandx}/
 * {@code ROLE_SUPERADMIN} appear). None mock the converter and re-derive expected scope.
 *
 * <p>The probe path {@code /whoami} is an ungoverned (non-public, non-infra) path, so it
 * falls to {@code anyExchange().authenticated()} — exactly the surface that proves "did
 * the token authenticate at all, and as which brand", isolated from the coarser role
 * gates ({@link SecurityConfigPathRulesTest} covers those).
 */
class MultiIssuerSecuritySliceTest extends SecuritySliceSupport {

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;   // NOT trusted
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        // Multi-issuer registry: brand-X + brand-Y trusted; rogue is NOT listed.
        // admin-bff DomainRegistry ctor = (singleIssuer, issuersCsv).
        String issuersCsv = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuersCsv);
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode, the resolver swap is taken")
                .isTrue();

        // REAL resolver bean (per-issuer manager + Casdoor converter), built exactly
        // as TenancyResourceServerConfig contributes it. No back-compat jwk-set-uri,
        // so each brand decoder discovers from its own issuer (the in-process server).
        // admin-bff TenancyResourceServerConfig ctor = (registry, backCompatIssuer, backCompatJwkSetUri,
        // mfaEnabled, mfaFreshnessWindowMillis). MFA OFF (dark default) for this slice.
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600_000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                net.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);

        client = sliceClient(registry, provider(resolver), new AuthoritiesController());
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    // ── (a) trusted issuer resolves + DOMAIN_<x> authority emitted ────────────

    @Test
    void userSituational_brandXToken_authenticates_andEmitsDomainXAuthority() {
        String token = brandX.mint("user-x", List.of("admin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("brand-X token resolves to brand-X's manager and is stamped DOMAIN_brandx")
                        .contains("DOMAIN_brandx")
                        // the Casdoor converter ran: roles -> ROLE_, floor ROLE_USER
                        .contains("ROLE_ADMIN")
                        .contains("ROLE_USER")
                        // and NOT the other brand's domain
                        .doesNotContain("DOMAIN_brandy"));
    }

    @Test
    void multiUser_brandYToken_authenticates_andEmitsDomainYAuthority() {
        String token = brandY.mint("user-y", List.of("mod"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .contains("DOMAIN_brandy")
                        .contains("ROLE_MOD")
                        .doesNotContain("DOMAIN_brandx"));
    }

    // ── (b) UNKNOWN / untrusted issuer -> 401 fail-closed ─────────────────────

    @Test
    void crossUser_unknownIssuerToken_is401_failClosed_neverDefaultAccept() {
        // The rogue issuer is a perfectly valid, well-formed, correctly-signed JWT —
        // it is just NOT in app.tenancy.issuers. The per-issuer resolver returns
        // Mono.empty() for it, which the JwtIssuerReactiveAuthenticationManagerResolver
        // surfaces as an authentication failure: 401. There is NO default manager that
        // would let an unlisted issuer through.
        String token = rogue.mint("attacker", List.of("admin", "superadmin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_garbageBearer_is401() {
        // A non-JWT bearer also fails closed (no issuer to resolve).
        client.get().uri("/whoami")
                .header("Authorization", "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void noBearer_is401() {
        // No credential at all on an authenticated() surface -> 401.
        client.get().uri("/whoami")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (c) signature mismatch / cross-brand isolation -> 401 ─────────────────

    @Test
    void crossUser_brandXSignedTokenWithBrandYIssuer_sigMismatch_is401() {
        // SECURITY: forge a token whose PAYLOAD claims brand-Y's iss but is SIGNED by
        // brand-X's key. The resolver picks brand-Y's manager (off the iss claim), whose
        // decoder fetches brand-Y's JWKS — the brand-X signature does NOT verify there ->
        // 401. This is the load-bearing "sig mismatch" assertion: an attacker cannot mint
        // a brand-Y identity with a key they control.
        String forged = brandX.mintWithClaims("attacker", Map.of(
                "iss", brandY.issuerUri(),
                "roles", List.of(Map.of("name", "superadmin"))));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + forged)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_brandYToken_cannotImpersonateBrandX() {
        // A brand-Y-issued token carries brand-Y's `iss` and is signed by brand-Y's
        // key. It validates ONLY against brand-Y's manager. It can NEVER authenticate
        // AS brand-X: there is no path by which presenting a brand-Y token yields a
        // DOMAIN_brandx authority.
        String token = brandY.mint("user-y", List.of("admin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("a brand-Y token is scoped to brand-Y; it can NEVER become brand-X")
                        .contains("DOMAIN_brandy")
                        .doesNotContain("DOMAIN_brandx"));
    }

    @Test
    void crossUser_tamperedSignature_is401() {
        // A brand-X token whose signature is corrupted fails brand-X's manager
        // validation -> 401 (not silently accepted). Same fail-closed posture.
        String token = brandX.mint("user-x", List.of("admin"));
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + tampered)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (d) reserved-authority forge defense (DOMAIN_/ROLE_/MFA_ injection) ────

    @Test
    void crossUser_permissionsClaim_cannotForgeReservedAuthorities() {
        // SECURITY: a brand-Y token whose `permissions` claim tries to inject
        // DOMAIN_brandx (forged tenant), ROLE_SUPERADMIN (forged super-role) and an
        // MFA_SATISFIED style authority must NOT escalate. The CasdoorAuthorities
        // reserved-prefix filter strips ROLE_/DOMAIN_ permission entries; the ONLY
        // DOMAIN_ authority is the cryptographically-validated iss. (admin-bff reserves
        // ROLE_/DOMAIN_; MFA_ is not in this repo's reserved set, documented in PR body.)
        String token = brandY.mintWithClaims("attacker-y", Map.of(
                "roles", List.of(Map.of("name", "user")),
                "permissions", List.of("DOMAIN_brandx", "ROLE_SUPERADMIN", "reports:read")));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("forged DOMAIN_/ROLE_ permission entries are stripped; iss-derived DOMAIN wins")
                        .contains("DOMAIN_brandy")
                        .doesNotContain("DOMAIN_brandx")
                        .doesNotContain("ROLE_SUPERADMIN")
                        // a non-reserved permission still flows through verbatim
                        .contains("reports:read"));
    }

    @Test
    void crossUser_rolesClaimNamedDomain_cannotForgeTenantAuthority() {
        // A roles entry "DOMAIN_brandx" is ALWAYS ROLE_-prefixed first -> "ROLE_DOMAIN_BRANDX"
        // (an inert non-tenant authority), so it can never satisfy a DOMAIN_ tenant check.
        String token = brandY.mintWithClaims("attacker-y", Map.of(
                "roles", List.of(Map.of("name", "DOMAIN_brandx"), Map.of("name", "user"))));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("a roles entry can never forge a bare DOMAIN_ authority")
                        .contains("DOMAIN_brandy")
                        .doesNotContain("DOMAIN_brandx")
                        // it becomes the inert ROLE_DOMAIN_BRANDX, never a tenant authority
                        .contains("ROLE_DOMAIN_BRANDX"));
    }

    /** Echoes the authenticated principal's authorities — the simplest probe that
     *  proves which manager resolved the token and which authorities it emitted. */
    @RestController
    static class AuthoritiesController {
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
