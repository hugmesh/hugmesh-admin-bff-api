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
        return new DomainTheme(domain, preset, "dusk", "sharp", null, null, null,
                rendered, "studio");
    }

    private static DomainTheme selectionOnly(String domain, String preset) {
        return new DomainTheme(domain, preset, "dusk", "sharp", null, null, null);
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
        service.set(new DomainTheme("brandx", "nord", "light", "sharp", null, null, null),
                BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedCss()).isNull())
                .verifyComplete();
    }

    @Test
    void changingOnlyAHexOverrideCountsAsAChangedSelection() {
        service.set(withCss("brandx", "nord", css("#88c0d0")), ROOT, "studio").block();
        service.set(new DomainTheme("brandx", "nord", "dusk", "sharp", "#ff0088", null, null),
                BRANDX, "x-admin").block();

        StepVerifier.create(service.resolve("brandx"))
                .assertNext(t -> assertThat(t.renderedCss()).isNull())
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
