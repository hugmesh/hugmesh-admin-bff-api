package net.hugmesh.adminbff.matrixadmin;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * SHIPS-DARK proof for the ADMIN-only Matrix deactivate (hugmesh-mod-bff-api#23) — the
 * {@code BackingServiceEffectorWiringTest} shape. {@code MatrixAdminDeactivateClientTest} pins
 * that the client HONOURS {@code enabled}; this pins that {@code enabled} DEFAULTS to false, in
 * both layers that could flip it:
 * <ul>
 *   <li>the {@code @Value("${matrix-admin.enabled:false}")} default in {@link MatrixAdminConfig}
 *       (no properties at all), and</li>
 *   <li>the shipped {@code application.yml} {@code ${MATRIX_ADMIN_DEACTIVATE_ENABLED:false}}
 *       default (the yml loaded, no environment variable set).</li>
 * </ul>
 * The OS environment and JVM system properties are removed from the runner's environment, so a
 * developer's exported {@code MATRIX_ADMIN_DEACTIVATE_ENABLED} cannot make this pass or fail.
 */
class MatrixAdminDeactivateDarkByDefaultTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(ctx -> isolate(ctx.getEnvironment()))
            // Boot's converters (String -> Duration for the timeout / confirm-ttl @Values), as
            // the real application context has them.
            .withInitializer(ctx -> ctx.getBeanFactory()
                    .setConversionService(ApplicationConversionService.getSharedInstance()))
            .withBean(WebClient.Builder.class, WebClient::builder)
            .withBean(MatrixDeactivateProposalRepository.class,
                    () -> mock(MatrixDeactivateProposalRepository.class))
            .withUserConfiguration(MatrixAdminConfig.class);

    @Test
    void codeDefault_isDark() {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx.getBean(MatrixAdminDeactivateClient.class).enabled()).isFalse();
        });
    }

    @Test
    void shippedApplicationYml_isDark() {
        runner.withInitializer(ctx -> loadApplicationYml(ctx.getEnvironment())).run(ctx -> {
            assertThat(ctx).hasNotFailed();
            // The yml really was loaded (not silently absent, which would reduce this to the
            // code-default case above).
            assertThat(ctx.getEnvironment().getProperty("matrix-admin.deactivate.confirm-ttl"))
                    .isNotNull();
            assertThat(ctx.getEnvironment().getProperty("matrix-admin.enabled", Boolean.class))
                    .isFalse();
            assertThat(ctx.getBean(MatrixAdminDeactivateClient.class).enabled()).isFalse();
        });
    }

    @Test
    void explicitlyArmed_isArmed() {
        // Control: the property really reaches the bean, so the two dark results above are not
        // an artefact of a binding that ignores the property altogether.
        runner.withPropertyValues("matrix-admin.enabled=true").run(ctx ->
                assertThat(ctx.getBean(MatrixAdminDeactivateClient.class).enabled()).isTrue());
    }

    private static void isolate(ConfigurableEnvironment env) {
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
    }

    private static void loadApplicationYml(ConfigurableEnvironment env) {
        try {
            new YamlPropertySourceLoader()
                    .load("shipped-application-yml", new ClassPathResource("application.yml"))
                    .forEach(ps -> env.getPropertySources().addLast(ps));
        } catch (IOException e) {
            throw new IllegalStateException("application.yml not readable on the test classpath", e);
        }
    }
}
