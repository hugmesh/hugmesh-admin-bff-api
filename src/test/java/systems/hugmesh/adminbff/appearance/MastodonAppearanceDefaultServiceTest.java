package systems.hugmesh.adminbff.appearance;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.commons.web.ApiException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SERVICE-layer behaviour for {@link MastodonAppearanceDefaultService} over the real
 * repository slice — proves the "absence is honest" resolution (no admin default =
 * empty map, NOT a fabricated built-in guess), field/value validation (including the
 * typed boolean round-trip), brand isolation, and the never-silently-a-no-op empty-PUT
 * rejection. Delineated per the test standard:
 *
 * <ul>
 *   <li><b>BRAND-SITUATIONAL</b> — a single brand: an unconfigured brand resolves to an
 *       empty map; a put/get round-trip is durable; an unknown field, a bad enum value,
 *       a bad boolean value, and an empty prefs body are all a clean 400.</li>
 *   <li><b>CROSS-BRAND</b> — brand X's put never affects brand Y's resolved default.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, MastodonAppearanceDefaultRepository.class,
        MastodonAppearanceDefaultServiceTest.Cfg.class})
class MastodonAppearanceDefaultServiceTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class Cfg {
        @Bean MastodonAppearanceDefaultService service(MastodonAppearanceDefaultRepository repo) {
            return new MastodonAppearanceDefaultService(repo);
        }
    }

    @Autowired MastodonAppearanceDefaultService service;

    // ── BRAND-SITUATIONAL ────────────────────────────────────────────────────
    @Nested
    class BrandSituational {
        @Test
        void unconfiguredBrand_resolvesToEmptyMap_noFabricatedDefault() {
            assertThat(service.get("bs-1").block()).isEmpty();
        }

        @Test
        void put_thenGet_durableChoiceWins() {
            Map<String, Object> after = service.put(
                    Map.of("theme", "pastel-sky", "highContrast", true), "bs-2", "admin@x").block();
            assertThat(after).containsEntry("theme", "pastel-sky");
            assertThat(after).containsEntry("highContrast", true); // typed boolean, not "true" string
            assertThat(service.get("bs-2").block()).containsEntry("theme", "pastel-sky");
        }

        @Test
        void put_booleanAsStringIsAccepted_andTypedOnRead() {
            Map<String, Object> after = service.put(
                    Map.of("reducedMotion", "TRUE"), "bs-3", "admin@x").block();
            assertThat(after).containsEntry("reducedMotion", true);
        }

        @Test
        void put_unknownField_isBadRequest() {
            assertThatThrownBy(() -> service.put(Map.of("wallpaper", "sunset"), "bs-4", "admin@x").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void put_invalidEnumValue_isBadRequest() {
            assertThatThrownBy(() -> service.put(Map.of("layout", "triple-column"), "bs-5", "admin@x").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void put_invalidBooleanValue_isBadRequest() {
            assertThatThrownBy(() -> service.put(Map.of("highContrast", "maybe"), "bs-6", "admin@x").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void put_emptyPrefs_isBadRequest_neverASilentNoOp() {
            assertThatThrownBy(() -> service.put(Map.of(), "bs-7", "admin@x").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(400);
        }

        @Test
        void blankDomain_isUnauthorized() {
            assertThatThrownBy(() -> service.get("  ").block())
                    .isInstanceOf(ApiException.class)
                    .extracting(e -> ((ApiException) e).status().value()).isEqualTo(401);
        }

        @Test
        void put_allFields_areAccepted() {
            Map<String, Object> valid = Map.of(
                    "theme", "mono",
                    "accent", "peach",
                    "appearance", "light",
                    "layout", "multi",
                    "density", "compact",
                    "mediaCorners", "square",
                    "font", "dyslexic",
                    "textSize", "xl",
                    "highContrast", true,
                    "reducedMotion", false);
            Map<String, Object> resolved = service.put(valid, "bs-8", "admin@x").block();
            for (var entry : valid.entrySet()) {
                assertThat(resolved).containsEntry(entry.getKey(), entry.getValue());
            }
        }
    }

    // ── CROSS-BRAND ───────────────────────────────────────────────────────────
    @Nested
    class CrossBrand {
        @Test
        void brandIsolation_putInBrandXDoesNotAffectBrandY() {
            service.put(Map.of("theme", "mono"), "cb-x", "admin@x").block();
            assertThat(service.get("cb-y").block()).isEmpty();
        }
    }
}
