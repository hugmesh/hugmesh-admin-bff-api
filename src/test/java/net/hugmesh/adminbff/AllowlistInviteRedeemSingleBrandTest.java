package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * hugmesh-admin-bff-api#111 on a SINGLE-BRAND install: {@code app.tenancy.issuers} names one
 * brand and there is no pin, so the register gate's {@code fallback()} is that brand, not
 * {@code "default"}. A domainless admin's invite must be stamped with that brand.
 */
@TestPropertySource(properties = {
        "app.tenancy.issuers=https://id.brand-a.test=brand-a",
        "app.tenancy.registration-domain="})
class AllowlistInviteRedeemSingleBrandTest extends AllowlistInviteRedeemSlice {

    /** (d) the stamp is the only brand, and the gate redeems it. */
    @Test
    void domainlessAdminInvite_isStampedWithTheOnlyBrand() {
        assertThat(registrationDomains.fallback()).isEqualTo("brand-a");

        invite(asDomainlessAdmin(), "{\"email\":\"single-brand@gmail.com\"}").expectStatus().isOk();

        assertThat(stampsOf("google", "single-brand@gmail.com")).containsExactly("brand-a");
        gateRead("google", "single-brand@gmail.com").expectStatus().isOk()
                .expectBody().jsonPath("$.invited").isEqualTo(true);
        registerGoogle("single-brand@gmail.com").expectStatus().isOk();
    }
}
