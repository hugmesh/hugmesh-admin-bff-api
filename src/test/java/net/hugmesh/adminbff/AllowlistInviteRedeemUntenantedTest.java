package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;
import net.hugmesh.authcore.account.AccountStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

/**
 * hugmesh-admin-bff-api#111 on an UNCONFIGURED install: no {@code app.tenancy.issuers}, no
 * issuer-uri, no registration pin, so the {@code DomainRegistry} is literally empty and the
 * register gate's {@code fallback()} is {@link AccountStore#DEFAULT_DOMAIN}. This is the
 * compose-lane shape the issue measured.
 *
 * <p>Before the fix a domainless admin's invite was stamped {@code NO_DOMAIN}: the console
 * answered 200 and listed it, the gate read {@code "default"} and never found it, and the
 * console hid the one {@code "default"} row the gate could see.
 */
@TestPropertySource(properties = {
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=",
        "app.tenancy.issuers=",
        "app.tenancy.registration-domain="})
class AllowlistInviteRedeemUntenantedTest extends AllowlistInviteRedeemSlice {

    @Test
    void registryIsReallyEmpty_soTheGateReadsDefault() {
        assertThat(registrationDomains.fallback()).isEqualTo(AccountStore.DEFAULT_DOMAIN);
    }

    /** (a) invite from the console, then redeem through the gate read user-bff makes. */
    @Test
    void domainlessAdminInvite_isRedeemableByTheGate() {
        invite(asDomainlessAdmin(), "{\"email\":\"redeem-a@gmail.com\",\"discord\":\"redeemdiscorda\"}")
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.emails").value(hasItem("redeem-a@gmail.com"))
                .jsonPath("$.discord").value(hasItem("redeemdiscorda"));

        assertThat(stampsOf("google", "redeem-a@gmail.com")).containsExactly(AccountStore.DEFAULT_DOMAIN);
        assertThat(stampsOf("discord", "redeemdiscorda")).containsExactly(AccountStore.DEFAULT_DOMAIN);

        gateRead("google", "redeem-a@gmail.com").expectStatus().isOk()
                .expectBody().jsonPath("$.invited").isEqualTo(true);
        gateRead("discord", "redeemdiscorda").expectStatus().isOk()
                .expectBody().jsonPath("$.invited").isEqualTo(true);
    }

    /** (a), admin-bff's own register leg: the untokened register gate admits the invite. */
    @Test
    void domainlessAdminInvite_admitsTheUntokenedRegistration() {
        invite(asDomainlessAdmin(), "{\"email\":\"redeem-reg@gmail.com\"}").expectStatus().isOk();
        registerGoogle("redeem-reg@gmail.com").expectStatus().isOk();
    }

    /** (b) the console lists the seeded {@code "default"} row the gate can actually see. */
    @Test
    void consoleList_showsTheSeededDefaultRow() {
        // Seeded at test time, exactly as AccountStore.seedAdmins() writes it (the seed email's
        // derived username is reserved, so the console's own invite would refuse it).
        store.inviteEmail("admin@hugmesh.net", AccountStore.DEFAULT_DOMAIN).block();
        asDomainlessAdmin().get().uri("/bff/admin/allowlist").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.emails").value(hasItem("admin@hugmesh.net"));
    }

    /** The revoke is scoped the same way, so the console can remove what it lists. */
    @Test
    void domainlessAdminUninvite_removesTheRedeemableRow() {
        invite(asDomainlessAdmin(), "{\"email\":\"revoke-me@gmail.com\"}").expectStatus().isOk();
        uninvite(asDomainlessAdmin(), "{\"email\":\"revoke-me@gmail.com\"}")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.emails").value(not(hasItem("revoke-me@gmail.com")));
        assertThat(stampsOf("google", "revoke-me@gmail.com")).isEmpty();
        gateRead("google", "revoke-me@gmail.com").expectBody().jsonPath("$.invited").isEqualTo(false);
    }
}
