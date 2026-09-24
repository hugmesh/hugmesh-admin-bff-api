package net.hugmesh.adminbff.backingservices;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SHIPS-DARK proof for the real managed-mode effector — the {@code BackupEffectorWiringTest} /
 * {@code NodeStorageReconcilerWiringTest} shape.
 *
 * <p>Two things are pinned, and both matter for a release nobody has exercised on a cluster:
 * <ul>
 *   <li><b>The default is dark.</b> With no property set, the seam is the logging
 *       {@link NoopBackingServiceEffector} and {@link Fabric8BackingServiceEffector} is not even
 *       constructed, so no BFF dials a cluster at defaults and a recorded managed mode stays
 *       durable intent.</li>
 *   <li><b>Exactly one bean in every mode.</b> The two beans are gated by the SAME property with
 *       mutually-exclusive values, so neither "both registered" nor "none registered" is
 *       reachable — the failure that relying on {@code @ConditionalOnMissingBean} ordering
 *       between two plain {@code @Configuration} classes would leave open.</li>
 * </ul>
 */
class BackingServiceEffectorWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(BackingServiceEffectorConfig.class);

    @Test
    void defaultsToTheDarkNoop() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(BackingServiceEffector.class);
            assertThat(ctx.getBean(BackingServiceEffector.class))
                    .isInstanceOf(NoopBackingServiceEffector.class);
            assertThat(ctx.getBean(BackingServiceEffector.class).isReal()).isFalse();
            assertThat(ctx).doesNotHaveBean(Fabric8BackingServiceEffector.class);
        });
    }

    @Test
    void explicitlyFalseStaysDark() {
        runner.withPropertyValues("app.backing-services.effector.enabled=false").run(ctx -> {
            assertThat(ctx).hasSingleBean(BackingServiceEffector.class);
            assertThat(ctx.getBean(BackingServiceEffector.class))
                    .isInstanceOf(NoopBackingServiceEffector.class);
        });
    }

    @Test
    void trueWiresTheRealFanOutWriter() {
        runner.withPropertyValues("app.backing-services.effector.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(BackingServiceEffector.class);
            BackingServiceEffector effector = ctx.getBean(BackingServiceEffector.class);
            assertThat(effector).isInstanceOf(Fabric8BackingServiceEffector.class);
            // isReal() is what BackingServiceModeReconciler logs off — a real effector that
            // reported false would make every reconcile pass look like a no-op in the logs.
            assertThat(effector.isReal()).isTrue();
        });
    }

    @Test
    void theRealEffectorIsNotGivenANamespace() {
        // Decision 34a's fan-out has no single namespace to configure: the namespace comes from
        // the service's own plan entry. If a namespace property ever appears on this bean, that
        // is the single-object design creeping back in.
        runner.withPropertyValues("app.backing-services.effector.enabled=true").run(ctx -> {
            assertThat(Fabric8BackingServiceEffector.class.getDeclaredConstructors()).hasSize(1);
            assertThat(Fabric8BackingServiceEffector.class.getDeclaredConstructors()[0]
                    .getParameterTypes())
                    .containsExactly(Fabric8BackingServiceEffector.ClientFactory.class);
        });
    }
}
