package systems.hugmesh.adminbff.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The PROD-profile {@link InternalSurfaceTokenBootGuard} fail-fast contract — the sibling of
 * auth-core's {@code InternalSurfaceBootGuardTest} (which pins the mTLS half of the same
 * boundary). Without a configured internal-service credential the {@code /bff/internal/**}
 * subtree would degrade to its legacy unauthenticated behaviour while the fe-gateway's
 * {@code /bff/**} route still reaches it, so the guard aborts context refresh instead. The
 * bean is only ever created under {@code @Profile("!dev & !test")}, so dev/test never reach it.
 */
class InternalSurfaceTokenBootGuardTest {

    @Test
    void refusesToBoot_whenCredentialIsUnset() {
        assertThatThrownBy(() -> new InternalSurfaceTokenBootGuard("").afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("REFUSING TO BOOT")
                .hasMessageContaining("/bff/internal/**")
                .hasMessageContaining("INTERNAL_TOKEN");
    }

    @Test
    void refusesToBoot_whenCredentialIsNull() {
        assertThatThrownBy(() -> new InternalSurfaceTokenBootGuard(null).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("REFUSING TO BOOT");
    }

    @Test
    void refusesToBoot_whenCredentialIsWhitespaceOnly() {
        // A Secret that resolved to whitespace is just as unarmed as an absent one.
        assertThatThrownBy(() -> new InternalSurfaceTokenBootGuard("   ").afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void boots_whenCredentialIsConfigured() {
        assertThatCode(() -> new InternalSurfaceTokenBootGuard("s3cret").afterSingletonsInstantiated())
                .doesNotThrowAnyException();
    }
}
