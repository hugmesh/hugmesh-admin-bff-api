package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.hugmesh.adminbff.lease.LeaderElection;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Decision 101 = B through a REAL Spring context, not just the bare properties object.
 *
 * <p>{@link HeadscaleAclPolicyModeGuardTest} pins the Java field default and the gate method.
 * Neither is what a deployed BFF runs with: at boot the {@code app.registry.headscale-acl.*}
 * values come from {@code application.yml}, whose placeholders override the Java field
 * defaults. That file had drifted once already — until 2026-09-23 it carried no
 * {@code policy-mode} or {@code ssh-user} key and still named the nonexistent
 * {@code headscale.headscale.svc} base URL, although the Java class had been corrected. So these
 * tests load the SHIPPED {@code application.yml} and assert what the wired context actually
 * holds:
 * <ul>
 *   <li>the default context declares {@code database} (headscale's spelling) and stays DARK —
 *       the Noop client is the only policy client;</li>
 *   <li>{@code enabled=true} alone wires the real client (the default is now the decided
 *       target, so it does not trip the gate);</li>
 *   <li>{@code enabled=true} with {@code file} — or the old non-headscale {@code db} — still
 *       FAILS THE CONTEXT, including when set through the deployment's env-var placeholder.</li>
 * </ul>
 */
class HeadscaleAclWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(HeadscaleAclConfig.class)
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withBean(WebClient.Builder.class, WebClient::builder)
            .withBean(DeviceRegistryExportService.class, () -> mock(DeviceRegistryExportService.class))
            .withBean(LeaderElection.class, () -> mock(LeaderElection.class));

    @Test
    void shippedApplicationYml_defaultContextDeclaresDatabaseMode_andStaysDark() {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            HeadscaleAclProperties props = ctx.getBean(HeadscaleAclProperties.class);
            assertThat(props.getPolicyMode()).isEqualTo("database");
            assertThat(props.isEnabled()).isFalse();
            assertThat(props.getBaseUrl()).isEqualTo("http://headscale.hugmesh-pki.svc.cluster.local:8080");
            assertThat(props.getSshUser()).isEqualTo("admin");
            assertThat(ctx).hasSingleBean(HeadscalePolicyClient.class);
            assertThat(ctx.getBean(HeadscalePolicyClient.class)).isInstanceOf(NoopHeadscalePolicyClient.class);
        });
    }

    @Test
    void enabledWithTheShippedDefaultMode_wiresTheRealPushClient() {
        runner.withPropertyValues("app.registry.headscale-acl.enabled=true").run(ctx -> {
            assertThat(ctx).hasNotFailed();
            assertThat(ctx).hasSingleBean(HeadscalePolicyClient.class);
            assertThat(ctx.getBean(HeadscalePolicyClient.class))
                    .isInstanceOf(WebClientHeadscalePolicyClient.class);
        });
    }

    @Test
    void enabledInFileMode_stillFailsTheContext_namingTheMismatch() {
        runner.withPropertyValues("app.registry.headscale-acl.enabled=true",
                        "app.registry.headscale-acl.policy-mode=file")
                .run(ctx -> assertStartupRefused(ctx.getStartupFailure(), "policy-mode='file'"));
    }

    @Test
    void enabledWithTheOldDbSpelling_failsTheContext() {
        runner.withPropertyValues("app.registry.headscale-acl.enabled=true",
                        "app.registry.headscale-acl.policy-mode=db")
                .run(ctx -> assertStartupRefused(ctx.getStartupFailure(), "'db' was this BFF's old spelling"));
    }

    @Test
    void fileModeThroughTheDeploymentEnvPlaceholders_failsTheContext() {
        // The deployment sets APP_REGISTRY_HEADSCALE_ACL_* env vars, which application.yml's
        // placeholders read — this is the path an operator actually uses.
        runner.withPropertyValues("APP_REGISTRY_HEADSCALE_ACL_ENABLED=true",
                        "APP_REGISTRY_HEADSCALE_ACL_POLICY_MODE=file")
                .run(ctx -> assertStartupRefused(ctx.getStartupFailure(), "policy-mode='file'"));
    }

    @Test
    void everyDeclaredKey_isReachableThroughItsDeploymentEnvPlaceholder() {
        // A key missing from application.yml is invisible to its APP_REGISTRY_HEADSCALE_ACL_*
        // placeholder, so an operator's override would silently not apply.
        runner.withPropertyValues("APP_REGISTRY_HEADSCALE_ACL_POLICY_MODE=file",
                        "APP_REGISTRY_HEADSCALE_ACL_SSH_USER=ops",
                        "APP_REGISTRY_HEADSCALE_ACL_BASE_URL=http://hs.example:8080")
                .run(ctx -> {
                    HeadscaleAclProperties props = ctx.getBean(HeadscaleAclProperties.class);
                    assertThat(props.getPolicyMode()).isEqualTo("file");
                    assertThat(props.getSshUser()).isEqualTo("ops");
                    assertThat(props.getBaseUrl()).isEqualTo("http://hs.example:8080");
                });
    }

    private static void assertStartupRefused(Throwable failure, String detail) {
        assertThat(failure).as("the context must fail to start").isNotNull();
        Throwable root = failure;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        assertThat(root).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("POLICY-MODE MISMATCH")
                .hasMessageContaining("expected 'database'")
                .hasMessageContaining(detail);
    }
}
