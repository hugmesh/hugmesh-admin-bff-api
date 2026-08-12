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
        return new CreateDomainRequest(clusterDomain, "acme", "Acme Inc", "vault:pki/acme",
                "acme", "acme-org", "tag:acme", null /* enabled omitted -> defaults true */);
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
                "renamed", null, null, null, null, null, false);
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
        UpdateDomainRequest req = new UpdateDomainRequest(null, null, null, null, null, null, true);
        assertThatThrownBy(() -> svc().update("ghost.test", req).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404));
    }

    @Test
    void list_returnsCreatedDomains() {
        DomainRegistryService svc = svc();
        svc.create(create("beta.test"), "superadmin@infra").block();
        svc.create(create("alpha.test"), "superadmin@infra").block();
        var all = svc.list().collectList().block();
        assertThat(all).extracting(DomainRegistration::clusterDomain)
                .containsExactly("alpha.test", "beta.test");
    }
}
