package net.hugmesh.adminbff.workload;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

/**
 * Test fixtures that build {@link PrincipalDomain}s + {@link org.springframework.security.core.Authentication}s
 * from synthetic Casdoor JWTs through the SAME {@code PrincipalDomain.of(auth, registry)} path the
 * controllers use, so the workload-console tests exercise the real issuer-&gt;domain derivation.
 */
final class WorkloadScopeFixtures {

    private WorkloadScopeFixtures() {
    }

    static final String BRANDX_ISSUER = "https://idp.brandx.example";
    static final String BRANDY_ISSUER = "https://idp.brandy.example";

    static final DomainRegistry REGISTRY = new DomainRegistry("",
            BRANDX_ISSUER + "=brandx," + BRANDY_ISSUER + "=brandy");

    private static String issuerFor(String domain) {
        return "brandy".equals(domain) ? BRANDY_ISSUER : BRANDX_ISSUER;
    }

    static JwtAuthenticationToken adminAuth(String domain) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("admin-" + domain).issuer(issuerFor(domain))
                .claim("roles", List.of("admin")).build();
        return new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    static JwtAuthenticationToken superadminAuth() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("root").issuer(BRANDX_ISSUER)
                .claim("roles", List.of("superadmin")).build();
        return new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    /**
     * The PRODUCTION custody-JWT shape for a google-provider superadmin: an opaque Casdoor
     * {@code sub} (matches no stored suspension localpart) with the person's identity in the
     * {@code email} claim — the claim native login derives {@code account.handle()} from.
     */
    static JwtAuthenticationToken superadminEmailAuth() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("casdoor-uuid-123").issuer(BRANDX_ISSUER)
                .claim("email", "root@brandx.example")
                .claim("roles", List.of("superadmin")).build();
        return new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    /** The discord-provider custody-JWT shape: no email, identity in {@code preferred_username}. */
    static JwtAuthenticationToken superadminPreferredUsernameAuth() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("casdoor-uuid-456").issuer(BRANDX_ISSUER)
                .claim("preferred_username", "root-discord")
                .claim("roles", List.of("superadmin")).build();
        return new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    /** An admin whose JWT carries an email identity claim ALONGSIDE the sub the grant is minted under. */
    static JwtAuthenticationToken adminEmailAuth(String domain) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("admin-" + domain).issuer(issuerFor(domain))
                .claim("email", "admin@" + domain + ".example")
                .claim("roles", List.of("admin")).build();
        return new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    static JwtAuthenticationToken userAuth(String domain) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("user-" + domain).issuer(issuerFor(domain))
                .claim("roles", List.of("user")).build();
        return new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    static PrincipalDomain adminScope(String domain) {
        return PrincipalDomain.of(adminAuth(domain), REGISTRY);
    }

    static PrincipalDomain superadminScope() {
        return PrincipalDomain.of(superadminAuth(), REGISTRY);
    }
}
