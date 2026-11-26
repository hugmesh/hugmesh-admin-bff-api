package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.CreateDomainRequest;
import net.hugmesh.adminbff.web.dto.UpdateDomainRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link DomainRegistryService} over a Liquibase-applied H2 (PG-compat) — proves the 012
 * changelog applies (domain_registry + UNIQUE) and the service contract: create stamps
 * {@code created_by_subject} + defaults {@code enabled}, duplicate cluster_domain is a
 * 409, update is a partial merge that never touches the PK / natural key / provenance,
 * and get/update on an unknown domain is a 404. Mirrors {@code DeviceRegistryServiceTest}
 * wiring.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainRegistryServiceTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM domain_registry").fetch().rowsUpdated().block();
    }

    private DomainRegistryService svc() {
        return new DomainRegistryService(new DomainRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainregistry.DomainRegistryRowRepository.class)));
    }

    private static CreateDomainRequest create(String clusterDomain) {
        return create(clusterDomain, "acme");
    }

    /** A create request whose SLUG (nsPrefix, decision 29a) is given explicitly. */
    private static CreateDomainRequest create(String clusterDomain, String slug) {
        return new CreateDomainRequest(clusterDomain, "acme", "Acme Inc", "vault:pki/acme",
                slug, "acme-org", "tag:acme", null /* enabled omitted -> defaults true */,
                null /* idp omitted -> defaults superdomain */);
    }

    @Test
    void create_stampsSubject_andDefaultsEnabledTrue_whenOmitted() {
        DomainRegistration saved = svc().create(create("acme.test"), "superadmin@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.clusterDomain()).isEqualTo("acme.test");
        assertThat(saved.createdBySubject()).isEqualTo("superadmin@infra");
        assertThat(saved.enabled()).isTrue(); // omitted in the request -> default true
    }

    @Test
    void create_duplicateClusterDomain_is409() {
        DomainRegistryService svc = svc();
        svc.create(create("dup.test"), "superadmin@infra").block();
        assertThatThrownBy(() -> svc.create(create("dup.test"), "other@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(409));
    }

    @Test
    void create_blankClusterDomain_is400() {
        assertThatThrownBy(() -> svc().create(create("   "), "superadmin@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400));
    }

    @Test
    void update_partialMerge_keepsUnsetFields_andSoftDisables() {
        DomainRegistryService svc = svc();
        DomainRegistration original = svc.create(create("up.test"), "creator@infra").block();

        // Only brand + enabled supplied; org/caRef/etc. are null -> keep current values.
        UpdateDomainRequest req = new UpdateDomainRequest(
                "renamed", null, null, null, null, null, false, null);
        DomainRegistration updated = svc.update("up.test", req).block();

        assertThat(updated).isNotNull();
        assertThat(updated.brand()).isEqualTo("renamed");     // changed
        assertThat(updated.enabled()).isFalse();              // soft-disabled
        assertThat(updated.org()).isEqualTo("Acme Inc");      // unset in req -> kept
        assertThat(updated.caRef()).isEqualTo("vault:pki/acme"); // kept
        // PK + natural key + provenance immutable across an update.
        assertThat(updated.id()).isEqualTo(original.id());
        assertThat(updated.clusterDomain()).isEqualTo("up.test");
        assertThat(updated.createdBySubject()).isEqualTo("creator@infra");
    }

    @Test
    void get_unknownDomain_is404() {
        assertThatThrownBy(() -> svc().get("ghost.test").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404));
    }

    @Test
    void update_unknownDomain_is404() {
        UpdateDomainRequest req = new UpdateDomainRequest(null, null, null, null, null, null, true, null);
        assertThatThrownBy(() -> svc().update("ghost.test", req).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404));
    }

    @Test
    void list_returnsCreatedDomains() {
        DomainRegistryService svc = svc();
        svc.create(create("beta.test", "beta"), "superadmin@infra").block();
        svc.create(create("alpha.test", "alpha"), "superadmin@infra").block();
        var all = svc.list().collectList().block();
        assertThat(all).extracting(DomainRegistration::clusterDomain)
                .containsExactly("alpha.test", "beta.test");
    }
    // ── decision 29 (2026-09-17): the slug rule, the idp vocabulary, the allocation ───

    @Test
    void create_withoutNsPrefix_is400_becauseNsPrefixIsTheSlug() {
        // DECISION 29a: nsPrefix IS the slug and names the Vault path secret/<slug>/casdoor.
        // Before this, a domain could be registered with no slug at all — unprovisionable,
        // and nothing said so until an ArgoCD sync failed.
        CreateDomainRequest noSlug = new CreateDomainRequest("noslug.test", "acme", "Acme Inc",
                "vault:pki/acme", null, "acme-org", "tag:acme", null, null);
        assertThatThrownBy(() -> svc().create(noSlug, "superadmin@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .hasMessageContaining("nsPrefix is required");
    }

    @Test
    void create_withANonLabelNsPrefix_is400() {
        // "bad.slug" would expand to the namespace "bad.slug-pki", which Kubernetes rejects.
        CreateDomainRequest badSlug = new CreateDomainRequest("bad.test", "acme", "Acme Inc",
                "vault:pki/acme", "bad.slug", "acme-org", "tag:acme", null, null);
        assertThatThrownBy(() -> svc().create(badSlug, "superadmin@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .hasMessageContaining("DNS-1123 label");
    }

    @Test
    void create_withAnUnknownIdp_is400() {
        // DECISION 29b: idp is a real column with a CLOSED vocabulary. Anything else would
        // sit in the row until the CHECK constraint or the generator's selector met it.
        CreateDomainRequest junkIdp = new CreateDomainRequest("idp.test", "acme", "Acme Inc",
                "vault:pki/acme", "idp", "acme-org", "tag:acme", null, "entra");
        assertThatThrownBy(() -> svc().create(junkIdp, "superadmin@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .hasMessageContaining("idp must be one of");
    }

    @Test
    void create_defaultsIdpToSuperdomain_andAllocatesTheMcsPair() {
        DomainRegistration saved = svc().create(create("fresh.test", "fresh"), "s@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.idp())
                .as("an omitted idp is the ride-the-central-Casdoor floor, matching the Studio "
                        + "Domain default and the absent-key reading of the KEYS manifest")
                .isEqualTo(DomainIdp.SUPERDOMAIN);
        assertThat(saved.selinuxLevel())
                .as("DECISION 29c: the writer allocates the MCS pair AT INSERT")
                .isEqualTo("s0:c" + McsCategoryAllocator.FLOOR_CATEGORY);
        assertThat(saved.selinuxLevelPg())
                .isEqualTo("s0:c" + (McsCategoryAllocator.FLOOR_CATEGORY + 1));
    }

    @Test
    void create_ownIdp_isStoredAsOwn() {
        CreateDomainRequest own = new CreateDomainRequest("own.test", "acme", "Acme Inc",
                "vault:pki/acme", "own", "acme-org", "tag:acme", null, DomainIdp.OWN);
        DomainRegistration saved = svc().create(own, "s@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.idp()).isEqualTo(DomainIdp.OWN);
    }

    @Test
    void create_duplicateSlug_onADifferentDomain_is409_notA500() {
        // Two domains sharing a slug would read ONE Vault document, secret/<slug>/casdoor.
        // The natural-key re-check cannot catch this (the winning row has a DIFFERENT
        // cluster_domain), so without an explicit slug check the DB constraint surfaces as a
        // raw DuplicateKeyException — a 500 for what is squarely a conflict.
        DomainRegistryService svc = svc();
        svc.create(create("first.test", "shared"), "s@infra").block();
        assertThatThrownBy(() -> svc.create(create("second.test", "shared"), "s@infra").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(409))
                .hasMessageContaining("first.test")
                .hasMessageContaining("secret/shared/casdoor");
    }

    @Test
    void update_changingNsPrefix_is409_becauseTheSlugIsImmutable() {
        DomainRegistryService svc = svc();
        svc.create(create("slug.test", "before"), "s@infra").block();

        UpdateDomainRequest rename = new UpdateDomainRequest(
                null, null, null, "after", null, null, null, null);
        assertThatThrownBy(() -> svc.update("slug.test", rename).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(409))
                .hasMessageContaining("nsPrefix is immutable");

        // ...and the stored slug is untouched.
        assertThat(svc.get("slug.test").block()).isNotNull()
                .extracting(DomainRegistration::nsPrefix).isEqualTo("before");
    }

    @Test
    void update_restatingTheCurrentNsPrefix_isAccepted() {
        // A console that round-trips the whole record must not be refused for echoing the slug.
        DomainRegistryService svc = svc();
        svc.create(create("echo.test", "echo"), "s@infra").block();
        UpdateDomainRequest echo = new UpdateDomainRequest(
                "renamed", null, null, "echo", null, null, null, null);
        DomainRegistration updated = svc.update("echo.test", echo).block();
        assertThat(updated).isNotNull();
        assertThat(updated.brand()).isEqualTo("renamed");
        assertThat(updated.nsPrefix()).isEqualTo("echo");
    }

    @Test
    void update_withAnUnknownIdp_is400() {
        DomainRegistryService svc = svc();
        svc.create(create("badidp.test", "badidp"), "s@infra").block();
        UpdateDomainRequest junk = new UpdateDomainRequest(
                null, null, null, null, null, null, null, "aws");
        assertThatThrownBy(() -> svc.update("badidp.test", junk).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400));
    }

    @Test
    void update_canFlipIdpToOwn() {
        DomainRegistryService svc = svc();
        svc.create(create("flip.test", "flip"), "s@infra").block();
        UpdateDomainRequest toOwn = new UpdateDomainRequest(
                null, null, null, null, null, null, null, DomainIdp.OWN);
        DomainRegistration updated = svc.update("flip.test", toOwn).block();
        assertThat(updated).isNotNull();
        assertThat(updated.idp()).isEqualTo(DomainIdp.OWN);
    }
}
