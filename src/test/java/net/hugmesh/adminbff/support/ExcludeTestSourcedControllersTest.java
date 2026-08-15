package net.hugmesh.adminbff.support;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.AdminController;

/**
 * Positive and negative controls for {@link ExcludeTestSourcedControllers#isTestSourced}.
 *
 * <p>Everything else in this area asserts that a leaked probe is CAUGHT. Nothing asserted that the
 * detector can tell the two code sources apart in the first place — and that is the one failure
 * that takes the whole mechanism down silently. {@code isTestSourced} answers by comparing a
 * class's {@code CodeSource} root to this classpath's {@code target/test-classes}; if that
 * comparison ever answered {@code false} for everything, the bean exclusion AND both of
 * {@code OpenApiSpecDumpTest}'s guards would degrade to no-ops at the same instant, the suite would
 * stay green, and every {@code ./mvnw test} would rewrite the committed OpenAPI contract with
 * phantom paths. That is exactly the mode this machinery exists to eliminate, so it may not depend
 * on an unasserted assumption.
 *
 * <p>It is worth being precise about why this is not already covered. Today a broken detector IS
 * loud, because the un-withdrawn {@code Probes} stand-in collides with {@link AdminController} on
 * {@code GET /bff/admin/allowlist} and the context fails to boot on an ambiguous mapping. But that
 * is an accident of the current layout, not a property of the design — and the guard's own failure
 * message advises developers to nest probe controllers inside their tests, which would remove the
 * collision and with it the accidental alarm. These two assertions are cheap and do not depend on
 * any of that.
 *
 * <p>No Spring context: this is a property of the classpath, and paying for a full boot to assert
 * it would discourage keeping it.
 */
class ExcludeTestSourcedControllersTest {

    @Test
    @DisplayName("a class compiled from src/test/java is recognised as test-sourced")
    void detectsTestSourcedClasses() {
        assertThat(ExcludeTestSourcedControllers.isTestSourced(ExcludeTestSourcedControllersTest.class))
                .as("this very test class lives in target/test-classes; if the detector cannot see "
                        + "that, it can no longer withdraw any leaked probe and the OpenAPI guards "
                        + "silently stop guarding")
                .isTrue();
    }

    @Test
    @DisplayName("a class compiled from src/main/java is NOT recognised as test-sourced")
    void doesNotFlagMainSourcedClasses() {
        assertThat(ExcludeTestSourcedControllers.isTestSourced(AdminController.class))
                .as("a production controller must never be withdrawn from the context, or the spec "
                        + "would lose real paths and the dump would be wrong in the other direction")
                .isFalse();
    }
}
