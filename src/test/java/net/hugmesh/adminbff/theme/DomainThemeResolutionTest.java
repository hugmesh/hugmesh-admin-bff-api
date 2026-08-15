package net.hugmesh.adminbff.theme;

import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.commons.security.PrincipalDomain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mesh default has to be findable again after it is written — over the real schema,
 * because this is a round-trip through a PRIMARY KEY and the bug it pins was a mismatch
 * between the key a write produced and the key a read asked for.
 *
 * <p>The default used to be written through the record (which trimmed
 * {@link PrincipalDomain#NO_DOMAIN} to {@code "no-domain"}) but read back as the raw
 * untrimmed sentinel. Both halves were individually plausible and the unit tests of
 * either half in isolation would have passed; the row simply never resolved, so a
 * superadmin could set the mesh default, see it saved, and watch every domain go on
 * rendering the shipped fallback. Only a write-then-read against one store shows it.
 *
 * <p>The 340-3 GRANT is deliberately NOT asserted here — this harness connects as the
 * container superuser, so it cannot see a missing GRANT at all. That is recorded in the
 * changelog rather than pretended at in a test that would pass either way.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DomainThemeRepository.class})
class DomainThemeResolutionTest {

    @Autowired DomainThemeRepository repo;
    @Autowired DatabaseClient db;

    private DomainThemeService service;

    @BeforeEach
    void wire() {
        service = new DomainThemeService(repo);
    }

    @BeforeEach
    @AfterEach
    void clear() {
        db.sql("DELETE FROM domain_theme").fetch().rowsUpdated().block();
    }

    private static DomainTheme theme(String domain, String preset) {
        return new DomainTheme(domain, preset, "dusk", "sharp", null, null, null);
    }

    private static final PrincipalDomain ROOT = PrincipalDomain.superadminFor("brandx");
    private static final PrincipalDomain BRANDX = PrincipalDomain.forDomain("brandx");

    @Test
    void aMeshWithNoRowsResolvesTheShippedFallback() {
        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.preset()).isEqualTo("dark");
                    assertThat(t.ramp()).isEqualTo(DomainTheme.DEFAULT_RAMP);
                })
                .verifyComplete();
    }

    @Test
    void aDomainWithNoRowOfItsOwnInheritsTheMeshDefault() {
        // THE REGRESSION. Written by a superadmin through the sentinel spelling...
        service.set(theme(PrincipalDomain.NO_DOMAIN, "nord"), ROOT, "root").block();

        // ...and it has to come back for a domain that has never been configured.
        StepVerifier.create(service.resolve("brandy"))
                .assertNext(t -> assertThat(t.preset()).isEqualTo("nord"))
                .verifyComplete();
    }

    @Test
    void theMeshDefaultResolvesWhenAskedForByEitherSpelling() {
        service.set(theme(DomainTheme.MESH_DEFAULT, "nord"), ROOT, "root").block();

        for (String spelling : new String[]{null, "", "   ", PrincipalDomain.NO_DOMAIN, "no-domain"}) {
            StepVerifier.create(service.resolve(spelling))
                    .assertNext(t -> assertThat(t.preset()).isEqualTo("nord"))
                    .verifyComplete();
        }
    }

    @Test
    void aDomainsOwnRowWinsOverTheMeshDefault() {
        service.set(theme(DomainTheme.MESH_DEFAULT, "nord"), ROOT, "root").block();
        service.set(theme("brandx", "pride"), BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.preset()).isEqualTo("pride"))
                .verifyComplete();
        // ...and the neighbour is untouched by it.
        StepVerifier.create(service.resolve("brandy"))
                .assertNext(t -> assertThat(t.preset()).isEqualTo("nord"))
                .verifyComplete();
    }

    @Test
    void clearingADomainReturnsItToTheMeshDefault() {
        service.set(theme(DomainTheme.MESH_DEFAULT, "nord"), ROOT, "root").block();
        service.set(theme("brandx", "pride"), BRANDX, "x-admin").block();

        service.clear("brandx", BRANDX).block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.preset()).isEqualTo("nord"))
                .verifyComplete();
    }

    @Test
    void everySpellingOfTheDefaultUpsertsTheSameSingleRow() {
        // The primary key is the domain; two spellings that both mean "the default" would
        // otherwise make "which wins?" unanswerable.
        service.set(theme(PrincipalDomain.NO_DOMAIN, "nord"), ROOT, "root").block();
        service.set(theme("", "pride"), ROOT, "root").block();
        service.set(theme("no-domain", "gruvbox"), ROOT, "root").block();

        Long rows = db.sql("SELECT count(*) AS c FROM domain_theme")
                .map(r -> r.get("c", Long.class)).one().block();
        assertThat(rows).isEqualTo(1L);

        StepVerifier.create(service.resolve("brandy"))
                .assertNext(t -> assertThat(t.preset()).isEqualTo("gruvbox"))
                .verifyComplete();
    }

    @Test
    void listShowsADomainAdminItsOwnRowAndTheDefaultButNotANeighboursRow() {
        service.set(theme(DomainTheme.MESH_DEFAULT, "nord"), ROOT, "root").block();
        service.set(theme("brandx", "pride"), ROOT, "root").block();
        service.set(theme("brandy", "gruvbox"), ROOT, "root").block();

        StepVerifier.create(service.list(BRANDX).collectList())
                .assertNext(list -> assertThat(list).extracting(DomainTheme::preset)
                        .containsExactlyInAnyOrder("pride", "nord"))
                .verifyComplete();
    }

    @Test
    void listShowsASuperadminEveryRow() {
        service.set(theme(DomainTheme.MESH_DEFAULT, "nord"), ROOT, "root").block();
        service.set(theme("brandx", "pride"), ROOT, "root").block();
        service.set(theme("brandy", "gruvbox"), ROOT, "root").block();

        StepVerifier.create(service.list(ROOT).collectList())
                .assertNext(list -> assertThat(list).hasSize(3))
                .verifyComplete();
    }

    @Test
    void listShowsAnUnresolvablePrincipalOnlyTheDefault() {
        service.set(theme(DomainTheme.MESH_DEFAULT, "nord"), ROOT, "root").block();
        service.set(theme("brandx", "pride"), ROOT, "root").block();

        StepVerifier.create(service.list(PrincipalDomain.forDomain(null)).collectList())
                .assertNext(list -> assertThat(list).extracting(DomainTheme::preset)
                        .containsExactly("nord"))
                .verifyComplete();
    }

    @Test
    void theHexCheckConstraintRejectsAMalformedColour() {
        StepVerifier.create(repo.upsert(new DomainTheme(
                        "brandx", "nord", "dusk", "soft", "not-a-colour", null, "x-admin")))
                .expectError()
                .verify();
    }
}
