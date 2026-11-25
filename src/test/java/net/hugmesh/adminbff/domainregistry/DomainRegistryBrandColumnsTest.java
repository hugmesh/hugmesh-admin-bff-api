package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import net.hugmesh.adminbff.web.dto.CreateDomainRequest;
import net.hugmesh.adminbff.web.dto.UpdateDomainRequest;
import net.hugmesh.commons.web.ApiException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * DECISION 87e = A over the real Liquibase-applied Postgres: changeset 380 adds the two columns,
 * the SUPERADMIN sets them on create and update, a partial update keeps them, an empty string
 * clears them, a value the renderer refuses is a 400, and the export carries what is stored.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainRegistryBrandColumnsTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM domain_registry").fetch().rowsUpdated().block();
    }

    private DomainRegistryRepository repo() {
        return new DomainRegistryRepository(R2dbcRepos.of(db, DomainRegistryRowRepository.class));
    }

    private DomainRegistryService svc() {
        return new DomainRegistryService(repo());
    }

    private static CreateDomainRequest create(String title, String url) {
        return new CreateDomainRequest("acme.test", "acme", "Org", null, "acme", null, null, null,
                null, title, url);
    }

    private static UpdateDomainRequest update(String title, String url) {
        return new UpdateDomainRequest(null, null, null, null, null, null, null, null, title, url);
    }

    private static int status(Throwable e) {
        return ((ApiException) e).status().value();
    }

    @Test
    void create_storesBoth_andTheExportCarriesThem() {
        DomainRegistration saved = svc().create(create("Acme Brand", "https://hs.acme.test"), "sa")
                .block();
        assertThat(saved.brandTitle()).isEqualTo("Acme Brand");
        assertThat(saved.headscaleUrl()).isEqualTo("https://hs.acme.test");
        var entry = DomainRegistryExportService.compile("fp", repo().findAll().collectList().block())
                .entries().get(0);
        assertThat(entry.brandTitle()).isEqualTo("Acme Brand");
        assertThat(entry.headscaleUrl()).isEqualTo("https://hs.acme.test");
    }

    @Test
    void create_withoutThem_storesNull() {
        DomainRegistration saved = svc().create(create(null, ""), "sa").block();
        assertThat(saved.brandTitle()).isNull();
        assertThat(saved.headscaleUrl()).isNull();
    }

    @Test
    void update_nullKeeps_valueSets_emptyClears() {
        DomainRegistryService svc = svc();
        svc.create(create("Acme Brand", "https://hs.acme.test"), "sa").block();

        DomainRegistration kept = svc.update("acme.test", update(null, null)).block();
        assertThat(kept.brandTitle()).isEqualTo("Acme Brand");
        assertThat(kept.headscaleUrl()).isEqualTo("https://hs.acme.test");

        DomainRegistration set = svc.update("acme.test", update("Renamed", null)).block();
        assertThat(set.brandTitle()).isEqualTo("Renamed");
        assertThat(set.headscaleUrl()).isEqualTo("https://hs.acme.test");

        DomainRegistration cleared = svc.update("acme.test", update("", "")).block();
        assertThat(cleared.brandTitle()).isNull();
        assertThat(cleared.headscaleUrl()).isNull();
    }

    @Test
    void create_aTitleTheRendererRefuses_is400_andStoresNothing() {
        assertThatThrownBy(() -> svc().create(create("{{HARBOR_PROJECT}}", null), "sa").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
        assertThat(repo().findAll().collectList().block()).isEmpty();
    }

    @Test
    void update_aUrlTheRendererRefuses_is400_andKeepsTheStoredOne() {
        DomainRegistryService svc = svc();
        svc.create(create(null, "https://hs.acme.test"), "sa").block();
        assertThatThrownBy(() -> svc.update("acme.test", update(null, "https://a b")).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(status(e)).isEqualTo(400));
        assertThat(svc.get("acme.test").block().headscaleUrl()).isEqualTo("https://hs.acme.test");
    }

    @Test
    void update_neverTouchesTheBandOneNinetyStatus_orThePair() {
        DomainRegistryService svc = svc();
        DomainRegistration created = svc.create(create(null, null), "sa").block();
        svc.recordReconcileAck("acme.test", true, 4L).block();
        DomainRegistration after = svc.update("acme.test", update("T", null)).block();
        assertThat(after.lastReconciledGeneration()).isEqualTo(4L);
        assertThat(after.appsetRegistered()).isTrue();
        assertThat(after.selinuxLevel()).isEqualTo(created.selinuxLevel());
    }
}
