package net.hugmesh.adminbff.storage;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SHIPS-DARK + ENV-LEVER proof for the node-storage reconciler — pins the
 * {@code @ConditionalOnProperty} wiring of {@link NodeStorageReconcilerConfig} (mirrors
 * {@code BackupEffectorWiringTest}) AND the environment variable the deployment flips it
 * with: {@code NODESTORAGE_RECONCILER_ENABLED} is the PROVEN canonical relaxed-binding env
 * form of {@code node-storage.reconciler.enabled} (dots &rarr; underscores, dashes REMOVED,
 * uppercase) — the name application.yml documents and the generator's deployment emits.
 *
 * <p>The env tests reproduce PRODUCTION resolution, not the runner's: a real boot attaches
 * {@link ConfigurationPropertySources} in {@code SpringApplication.prepareEnvironment}, and
 * only that attached source applies the dash-removing env mapping, so the initializer
 * attaches it explicitly over a fake {@code systemEnvironment} source (the runner alone
 * would resolve only the framework's dash&rarr;underscore legacy form and the canonical
 * name would silently not bind).
 */
class NodeStorageReconcilerWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(NodeStorageReconcilerConfig.class);

    /** The runner with ONE fake environment variable, resolved exactly as in production
     *  (fake {@code systemEnvironment} source + the Boot attach every real run gets). */
    private ApplicationContextRunner withEnvVar(String name, String value) {
        return runner.withInitializer(ctx -> {
            ctx.getEnvironment().getPropertySources().addFirst(new SystemEnvironmentPropertySource(
                    StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                    Map.of(name, value)));
            ConfigurationPropertySources.attach(ctx.getEnvironment());
        });
    }

    // ── DEFAULT (no property) -> the dark Noop writer ────────────────────────────────────

    @Test
    void writer_defaultsToNoop_shipsDark() {
        runner.run(ctx -> {
            assertThat(ctx).hasSingleBean(NodeStorageConfigMapWriter.class);
            assertThat(ctx.getBean(NodeStorageConfigMapWriter.class))
                    .isInstanceOf(NoopNodeStorageConfigMapWriter.class);
            assertThat(ctx).doesNotHaveBean(Fabric8NodeStorageConfigMapWriter.class);
        });
    }

    @Test
    void writer_explicitlyFalse_staysNoop() {
        runner.withPropertyValues("node-storage.reconciler.enabled=false").run(ctx -> {
            assertThat(ctx).hasSingleBean(NodeStorageConfigMapWriter.class);
            assertThat(ctx.getBean(NodeStorageConfigMapWriter.class))
                    .isInstanceOf(NoopNodeStorageConfigMapWriter.class);
        });
    }

    // ── property=true -> the REAL fabric8 writer (still single-bean) ─────────────────────

    @Test
    void writer_whenPropertyTrue_isFabric8_andSingleBean() {
        runner.withPropertyValues("node-storage.reconciler.enabled=true").run(ctx -> {
            assertThat(ctx).hasSingleBean(NodeStorageConfigMapWriter.class);
            assertThat(ctx.getBean(NodeStorageConfigMapWriter.class))
                    .isInstanceOf(Fabric8NodeStorageConfigMapWriter.class);
        });
    }

    // ── THE ENV LEVER (the deployment contract) ──────────────────────────────────────────

    @Test
    void envLever_NODESTORAGE_RECONCILER_ENABLED_enablesTheRealWriter() {
        withEnvVar("NODESTORAGE_RECONCILER_ENABLED", "true").run(ctx -> {
            // the canonical env name RESOLVES the dashed property…
            assertThat(ctx.getEnvironment().getProperty("node-storage.reconciler.enabled"))
                    .isEqualTo("true");
            // …and flips the wiring to the REAL writer, end to end.
            assertThat(ctx).hasSingleBean(NodeStorageConfigMapWriter.class);
            assertThat(ctx.getBean(NodeStorageConfigMapWriter.class))
                    .isInstanceOf(Fabric8NodeStorageConfigMapWriter.class);
        });
    }

    @Test
    void envLever_legacyUnderscoreForm_alsoEnables() {
        // The dash->underscore legacy form binds too (framework SystemEnvironmentPropertySource
        // resolution + Boot's legacy env mapping). The CANONICAL contract name stays
        // NODESTORAGE_RECONCILER_ENABLED — this pin only stops a silent regression for
        // deployments that used the underscore form.
        withEnvVar("NODE_STORAGE_RECONCILER_ENABLED", "true").run(ctx -> {
            assertThat(ctx.getBean(NodeStorageConfigMapWriter.class))
                    .isInstanceOf(Fabric8NodeStorageConfigMapWriter.class);
        });
    }

    @Test
    void envLever_wrongName_staysDark() {
        // Negative control for the rig itself: a flattened name maps to no property, so the
        // writer stays Noop — proving the positive tests pass because of the NAME, not
        // because the rig leaks any env value into the property space.
        withEnvVar("NODESTORAGERECONCILERENABLED", "true").run(ctx -> {
            assertThat(ctx.getEnvironment().getProperty("node-storage.reconciler.enabled"))
                    .isNull();
            assertThat(ctx.getBean(NodeStorageConfigMapWriter.class))
                    .isInstanceOf(NoopNodeStorageConfigMapWriter.class);
        });
    }
}
