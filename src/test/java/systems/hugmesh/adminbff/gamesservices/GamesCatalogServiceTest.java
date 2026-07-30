package systems.hugmesh.adminbff.gamesservices;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.GameCatalogEntryRequest;
import systems.hugmesh.adminbff.web.dto.GameDomainOfferRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The games-catalog SUPERADMIN service over real Liquibase-applied H2 repos — proves the
 * curation + offer business rules end to end:
 * <ul>
 *   <li>tag-only imageRef -&gt; 400 (digest-pin gate) and NOTHING is written;</li>
 *   <li>duplicate slug / offer -&gt; 409;</li>
 *   <li>offering an UNCURATED slug -&gt; 404 (the catalog-entry-must-exist gate);</li>
 *   <li>the two-tier offer: superadmin sets offered_by_superadmin + quota.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
// This class DELETEs the (Liquibase-seeded) game_server_catalog in @BeforeEach; the
// @DataR2dbcTest context (+ its H2 store) is cached and shared across the package, so mark
// it dirty AFTER_CLASS to force a fresh, re-seeded context for sibling classes that read the
// seed (e.g. GameServerCatalogRepositoryTest.seed_loaded).
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class GamesCatalogServiceTest {

    @Autowired DatabaseClient db;

    private GameServerCatalogRepository catalog;
    private GameServerDomainOfferRepository offers;
    private GamesCatalogService service;

    private static final String SHA64 =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private static final String PINNED = "ghcr.io/org/g@sha256:" + SHA64;

    @BeforeEach
    void setup() {
        // Isolate from the seeded catalog rows + any prior offers.
        db.sql("DELETE FROM game_server_domain_offer").fetch().rowsUpdated().block();
        db.sql("DELETE FROM game_server_catalog").fetch().rowsUpdated().block();
        catalog = new GameServerCatalogRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.gamesservices.GameServerCatalogR2dbcRepository.class));
        offers = new GameServerDomainOfferRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos.of(db, systems.hugmesh.adminbff.gamesservices.GameServerDomainOfferR2dbcRepository.class));
        service = new GamesCatalogService(catalog, offers);
    }

    private GameCatalogEntryRequest catalogReq(String slug, String imageRef) {
        return new GameCatalogEntryRequest(slug, "Display " + slug, imageRef,
                "GPL-3.0-or-later", "udp", 30000, null, "summary", true);
    }

    @Test
    void createCatalog_digestPinned_persists() {
        GameServerCatalogEntry saved =
                service.createCatalog(catalogReq("minetest", PINNED), "super@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.slug()).isEqualTo("minetest");
        assertThat(saved.createdBySubject()).isEqualTo("super@infra");
        assertThat(catalog.findBySlug("minetest").block()).isNotNull();
    }

    @Test
    void createCatalog_tagOnlyImageRef_is400_andNothingWritten() {
        StepVerifier.create(service.createCatalog(catalogReq("bad", "ghcr.io/org/g:latest"), "super@infra"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(400);
                })
                .verify();
        assertThat(catalog.findBySlug("bad").block()).isNull();
    }

    @Test
    void createCatalog_duplicateSlug_is409() {
        service.createCatalog(catalogReq("dup", PINNED), "super@infra").block();
        StepVerifier.create(service.createCatalog(catalogReq("dup", PINNED), "super@infra"))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(409))
                .verify();
    }

    @Test
    void updateCatalog_tagOnlyImageRef_is400() {
        service.createCatalog(catalogReq("upd", PINNED), "super@infra").block();
        GameCatalogEntryRequest tagUpdate = new GameCatalogEntryRequest(null, null,
                "ghcr.io/org/g:v2", null, null, null, null, null, null);
        StepVerifier.create(service.updateCatalog("upd", tagUpdate))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .verify();
    }

    // ── OFFERS: the creation gate + two-tier ─────────────────────────────────────

    @Test
    void createOffer_uncuratedSlug_is404_theCatalogMustExistGate() {
        StepVerifier.create(service.createOffer("acme.test",
                        new GameDomainOfferRequest("ghost", null, null, null), "super@infra"))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
    }

    @Test
    void createOffer_curatedSlug_setsGateAndQuota() {
        service.createCatalog(catalogReq("minetest", PINNED), "super@infra").block();
        GameServerDomainOffer offer = service.createOffer("acme.test",
                new GameDomainOfferRequest("minetest", null, null, 4), "super@infra").block();
        assertThat(offer).isNotNull();
        assertThat(offer.domain()).isEqualTo("acme.test");
        assertThat(offer.offeredBySuperadmin()).isTrue();   // TIER-1 gate flipped on
        assertThat(offer.enabledByAdmin()).isFalse();        // TIER-2 left to the domain admin
        assertThat(offer.maxInstances()).isEqualTo(4);
    }

    @Test
    void createOffer_duplicateDomainSlug_is409() {
        service.createCatalog(catalogReq("veloren", PINNED), "super@infra").block();
        service.createOffer("acme.test", new GameDomainOfferRequest("veloren", null, null, 1), "super@infra").block();
        StepVerifier.create(service.createOffer("acme.test",
                        new GameDomainOfferRequest("veloren", null, null, 1), "super@infra"))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(409))
                .verify();
    }

    @Test
    void updateOffer_withdraw_flipsGateOff() {
        service.createCatalog(catalogReq("xonotic", PINNED), "super@infra").block();
        service.createOffer("acme.test", new GameDomainOfferRequest("xonotic", null, null, 1), "super@infra").block();
        GameServerDomainOffer withdrawn = service.updateOffer("acme.test", "xonotic",
                new GameDomainOfferRequest(null, false, null, null)).block();
        assertThat(withdrawn).isNotNull();
        assertThat(withdrawn.offeredBySuperadmin()).isFalse();
    }

    @Test
    void updateOffer_unknownOffer_is404() {
        StepVerifier.create(service.updateOffer("acme.test", "nope",
                        new GameDomainOfferRequest(null, true, null, null)))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
    }
}
