package net.hugmesh.adminbff.servicecatalog;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

/**
 * Test fixtures that build a {@link PrincipalDomain} from a synthetic Casdoor JWT, mirroring
 * {@code SuspensionServiceDomainScopeTest} — the scope is resolved through the SAME
 * {@code PrincipalDomain.of(auth, registry)} path the controllers use, so the tests exercise
 * the real issuer->domain derivation (never a hand-set domain).
 *
 * <p>To build a SCOPED admin scope for a target {@code domain}, we look up the issuer that
 * maps to that domain in the supplied two-brand {@link DomainRegistry}.
 */
final class ScopeFixtures {

    private ScopeFixtures() {}

    /** The brandx/brandy issuers used by the appstore tests' two-brand registry. */
    static final String BRANDX_ISSUER = "https://idp.brandx.example";
    static final String BRANDY_ISSUER = "https://idp.brandy.example";

    /** A SCOPED admin PrincipalDomain whose issuer maps to {@code domain} in the registry. */
    static PrincipalDomain admin(String domain, DomainRegistry registry) {
        String issuer = issuerFor(domain);
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("admin-" + domain).issuer(issuer)
                .claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, registry);
    }

    /** An UNSCOPED superadmin PrincipalDomain (home issuer brandx). */
    static PrincipalDomain superadmin(DomainRegistry registry) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("root").issuer(BRANDX_ISSUER)
                .claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, registry);
    }

    private static String issuerFor(String domain) {
        return switch (domain) {
            case "brandx" -> BRANDX_ISSUER;
            case "brandy" -> BRANDY_ISSUER;
            default -> throw new IllegalArgumentException("no test issuer for domain " + domain);
        };
    }
}
