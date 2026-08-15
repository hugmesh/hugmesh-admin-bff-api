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
 * The rendered stylesheet is a CACHE of the selection, and the only interesting question
 * about a cache is when it must be thrown away.
 *
 * <p>The rule: a write that carries no render keeps the previous one ONLY if the
 * selection is unchanged. Getting this backwards is not a cosmetic bug — serving last
 * week's stylesheet for a selection saved thirty seconds ago renders the wrong brand
 * while the admin UI cheerfully reports the new one saved, which is the precise shape of
 * "my choice was ignored" that this feature line has already produced twice. An empty
 * sheet is the safe failure: every {@code var(--sd-*, <literal>)} falls back and the page
 * renders the shipped chrome. Visibly un-themed beats confidently wrong.
 *
 * <p>Run against real Postgres because {@code rendered_css} is a TEXT column holding
 * multi-kilobyte content with braces, newlines and percent signs — exactly the payload
 * that a binding or an escaping mistake mangles, and which an in-memory fake would not.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, DomainThemeRepository.class})
class DomainThemeCssServingTest {

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

    private static final PrincipalDomain ROOT = PrincipalDomain.superadminFor("brandx");
    private static final PrincipalDomain BRANDX = PrincipalDomain.forDomain("brandx");

    /** Shaped like the real thing: the Studio ships a :root:root block of token text. */
    private static String css(String accent) {
        return ":root:root {\n  --sd-accent: " + accent + ";\n  --sd-bg-0: #101014;\n}\n";
    }

    private static DomainTheme withCss(String domain, String preset, String rendered) {
        return decoratedWithCss(domain, preset, "none", rendered);
    }

    private static DomainTheme selectionOnly(String domain, String preset) {
        return decorated(domain, preset, "none");
    }

    /** The Studio's push: a full selection INCLUDING the decor axis, plus its render. */
    private static DomainTheme decoratedWithCss(String domain, String preset, String decor,
                                                String rendered) {
        return new DomainTheme(domain, preset, "dusk", "sharp", decor, null, null, null,
                rendered, "studio");
    }

    /** What the admin UI sends: a selection with no render, because it cannot derive one. */
    private static DomainTheme decorated(String domain, String preset, String decor) {
        return new DomainTheme(domain, preset, "dusk", "sharp", decor, null, null, null);
    }

    // ── the cache survives a round trip ─────────────────────────────────

    @Test
    void aRenderedSheetSurvivesStorageByteForByte() {
        String sheet = css("#88c0d0");
        service.set(withCss("brandx", "nord", sheet), ROOT, "root").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedCss()).isEqualTo(sheet.trim()))
                .verifyComplete();
    }

    @Test
    void aDomainWithNoRenderYetResolvesToNoStylesheetRatherThanAWrongOne() {
        service.set(selectionOnly("brandx", "nord"), ROOT, "root").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedCss()).isNull())
                .verifyComplete();
    }

    @Test
    void aDomainWithNoRowInheritsTheDefaultsRenderedSheet() {
        service.set(withCss(DomainTheme.MESH_DEFAULT, "nord", css("#88c0d0")), ROOT, "root").block();

        StepVerifier.create(service.resolve("brandy"))
                .assertNext(t -> assertThat(t.renderedCss()).contains("#88c0d0"))
                .verifyComplete();
    }

    // ── THE INVALIDATION RULE ───────────────────────────────────────────

    @Test
    void reSavingTheSameSelectionWithoutARenderKEEPSTheExistingOne() {
        // The admin UI cannot derive CSS, so an ordinary save from it carries none. That
        // must not wipe a perfectly valid stylesheet the Studio rendered earlier.
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "studio").block();
        service.set(selectionOnly("brandx", "nord"), BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.renderedCss()).contains("#88c0d0");
                    assertThat(t.updatedBy()).isEqualTo("x-admin");   // the write did happen
                })
                .verifyComplete();
    }

    @Test
    void changingTheSelectionWithoutARenderDROPSTheStaleOne() {
        // THE POINT OF THE WHOLE TEST CLASS. The old sheet is nord's; the selection is
        // now pride. Keeping it would paint nord and report pride.
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "studio").block();
        service.set(selectionOnly("brandx", "pride"), BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.preset()).isEqualTo("pride");
                    assertThat(t.renderedCss()).isNull();
                    assertThat(t.renderedBy()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void changingOnlyTheRampCountsAsAChangedSelection() {
        // Every axis repaints, not just the preset -- the ramp IS the colour scheme.
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "studio").block();
        service.set(new DomainTheme("brandx", "nord", "light", "sharp", "none", null, null, null),
                BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedCss()).isNull())
                .verifyComplete();
    }

    @Test
    void changingOnlyAHexOverrideCountsAsAChangedSelection() {
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "studio").block();
        service.set(new DomainTheme("brandx", "nord", "dusk", "sharp", "none", "#ff0088", null, null),
                BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedCss()).isNull())
                .verifyComplete();
    }

    // ── the decor axis, which is where the rule was actually broken ─────

    /**
     * THE STUCK-THEME BUG, end to end.
     *
     * <p>The Studio pushes a decorated selection and its render. A domain admin then saves
     * the SAME colours from a web UI that has no decor control at all, so the write carries
     * decor 'none' and no CSS. While {@code sameSelection} ignored decor that compared
     * EQUAL, the UwU sheet was kept, and the stored selection could no longer reproduce the
     * served stylesheet — with no control anywhere able to turn the decoration off.
     */
    @Test
    void aDecorationTheStudioSwitchedOnCanBeSwitchedOffFromTheAdminUi() {
        service.set(decoratedWithCss("brandx", "nord", "uwu", css("#88c0d0")), ROOT, "studio").block();

        service.set(decorated("brandx", "nord", "none"), BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.decor()).isEqualTo("none");
                    // The decorated sheet is gone: default chrome until a render for the
                    // NEW selection arrives. Un-themed beats confidently decorated.
                    assertThat(t.renderedCss()).isNull();
                    assertThat(t.renderedBy()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void changingOnlyTheDecorCountsAsAChangedSelection() {
        // Decoration is cosmetic but it is still IN the stylesheet, so an axis that moves
        // the bytes has to be able to invalidate them — same rule as the ramp.
        service.set(decoratedWithCss("brandx", "nord", "uwu", css("#88c0d0")), ROOT, "studio").block();
        service.set(decorated("brandx", "nord", "terminal"), BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.decor()).isEqualTo("terminal");
                    assertThat(t.renderedCss()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void reSavingTheSameSelectionIncludingItsDecorStillKEEPSTheRender() {
        // The other direction, so the fix above cannot be "invalidate on every write":
        // an identical selection, decor and all, must not throw a valid sheet away.
        service.set(decoratedWithCss("brandx", "nord", "uwu", css("#88c0d0")), ROOT, "studio").block();
        service.set(decorated("brandx", "nord", "uwu"), BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.renderedCss()).contains("#88c0d0");
                    assertThat(t.updatedBy()).isEqualTo("x-admin");   // the write did happen
                })
                .verifyComplete();
    }

    @Test
    void theChosenDecorSurvivesStorageSoTheSelectionCanReproduceTheRender() {
        service.set(decoratedWithCss("brandx", "nord", "sparkle", css("#88c0d0")), ROOT, "studio").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.decor()).isEqualTo("sparkle"))
                .verifyComplete();
    }

    @Test
    void aRowWrittenBeforeTheDecorColumnExistedReadsBackAsUndecorated() {
        // Changeset 340-5 is NOT NULL DEFAULT 'none', so rows that predate it are a
        // definite "no decoration" rather than a null the equality check would have to
        // guess at. Written as raw SQL because the record can no longer omit the axis.
        db.sql("INSERT INTO domain_theme (domain, preset) VALUES ('legacy', 'nord')")
                .fetch().rowsUpdated().block();

        StepVerifier.create(repo.findByDomain("legacy"))
                .assertNext(t -> assertThat(t.decor()).isEqualTo(DomainTheme.DEFAULT_DECOR))
                .verifyComplete();
    }

    @Test
    void aFreshRenderREPLACESTheOldOne() {
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "studio").block();
        service.set(withCss("brandx", "pride", css("#ff0088")), ROOT, "studio").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.renderedCss()).contains("#ff0088");
                    assertThat(t.renderedCss()).doesNotContain("#88c0d0");
                })
                .verifyComplete();
    }

    @Test
    void clearingADomainRemovesItsRenderTooRatherThanOrphaningIt() {
        service.set(withCss(DomainTheme.MESH_DEFAULT, "dark", css("#2e3436")), ROOT, "studio").block();
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "studio").block();

        service.clear("brandx", BRANDX).block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedCss()).contains("#2e3436"))
                .verifyComplete();
    }

    // ── the payload itself ──────────────────────────────────────────────

    @Test
    void aRealisticallyLargeSheetWithCssPunctuationSurvivesIntact() {
        // Braces, percent signs, newlines and quotes all round-trip: the real sheet is
        // ~7 KB of exactly this, and a binding mistake shows up as a truncated or mangled
        // stylesheet rather than an error.
        StringBuilder sb = new StringBuilder(":root:root {\n");
        for (int i = 0; i < 300; i++) {
            sb.append("  --sd-token-").append(i)
              .append(": rgba(0,0,0,.").append(i % 10).append(");\n");
        }
        sb.append("  --sd-flag-name: \"Progress Pride\";\n")
          .append("  --sd-grad: linear-gradient(90deg, #fff 0%, #000 100%);\n}\n");
        String sheet = sb.toString();

        service.set(withCss("brandx", "pride", sheet), ROOT, "studio").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> {
                    assertThat(t.renderedCss()).isEqualTo(sheet.trim());
                    assertThat(t.renderedCss()).contains("100%");
                    assertThat(t.renderedCss()).contains("\"Progress Pride\"");
                })
                .verifyComplete();
    }

    @Test
    void theRendererIsRecordedSoAStaleCacheIsIdentifiable() {
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "root").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedBy()).isEqualTo("studio"))
                .verifyComplete();
    }
}
