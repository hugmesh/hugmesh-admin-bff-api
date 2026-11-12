package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.commons.security.PrincipalDomain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * hugmesh-admin-bff-api#111 on a MULTI-BRAND mesh with NO registration pin: the register
 * gate's {@code fallback()} is {@link PrincipalDomain#NO_DOMAIN}, because nothing names the
 * brand and guessing would admit across brands. The #111 fix must change nothing here.
 *
 * <p>It also pins the fail-open this shape had before the fix: the domainless admin's
 * invite is (still, correctly) stamped {@code NO_DOMAIN}, and the gate's lookup is a plain
 * equality match, so an untokened registration that resolved to {@code NO_DOMAIN} FOUND that
 * row and was admitted. The gate now refuses the sentinel before it queries.
 */
@TestPropertySource(properties = {
        "app.tenancy.issuers=https://id.brand-a.test=brand-a,https://id.brand-b.test=brand-b",
        "app.tenancy.registration-domain="})
class AllowlistInviteRedeemMultiBrandTest extends AllowlistInviteRedeemSlice {

    /** (c) the stamp stays the sentinel and every register gate still refuses. */
    @Test
    void domainlessAdminInvite_staysNoDomain_andTheUntokenedGateRefuses() {
        assertThat(registrationDomains.fallback()).isEqualTo(PrincipalDomain.NO_DOMAIN);

        invite(asDomainlessAdmin(), "{\"email\":\"multi-brand@gmail.com\",\"discord\":\"multibranddiscord\"}")
                .expectStatus().isOk();
        assertThat(stampsOf("google", "multi-brand@gmail.com")).containsExactly(PrincipalDomain.NO_DOMAIN);
        assertThat(stampsOf("discord", "multibranddiscord")).containsExactly(PrincipalDomain.NO_DOMAIN);

        gateRead("google", "multi-brand@gmail.com").expectStatus().isOk()
                .expectBody().jsonPath("$.invited").isEqualTo(false);
        gateRead("discord", "multibranddiscord").expectStatus().isOk()
                .expectBody().jsonPath("$.invited").isEqualTo(false);
        registerGoogle("multi-brand@gmail.com").expectStatus().isForbidden();
        registerDiscord("multibranddiscord").expectStatus().isForbidden();
    }

    /** A brand admin (JWT from a configured issuer) keeps stamping its own brand. */
    @Test
    void brandAdminInvite_isStillStampedWithItsOwnBrand() {
        WebTestClient brandAAdmin = web.mutateWith(mockJwt()
                .jwt(j -> j.issuer("https://id.brand-a.test").claim("roles", java.util.List.of("admin")))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        invite(brandAAdmin, "{\"email\":\"brand-a-invite@gmail.com\"}").expectStatus().isOk();
        assertThat(stampsOf("google", "brand-a-invite@gmail.com")).containsExactly("brand-a");
        // The untokened gate on an unpinned multi-brand mesh names no brand, so it refuses
        // even a real brand's invite: the fail-closed shape is unchanged.
        registerGoogle("brand-a-invite@gmail.com").expectStatus().isForbidden();
    }
}
