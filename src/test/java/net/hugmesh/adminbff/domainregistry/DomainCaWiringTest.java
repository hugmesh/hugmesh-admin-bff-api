package net.hugmesh.adminbff.domainregistry;

import net.hugmesh.adminbff.lease.LeaderElection;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The CA effector's default-off wiring, through the SHIPPED {@code application.yml}
 * (hugmesh-admin-bff-api#99): dark by default (no Vault client, no scheduled loop), and an
 * enabled effector with no Vault token refuses to start instead of 403ing every tick.
 */
class DomainCaWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(DomainCaConfig.class)
            .withBean(DomainRegistryRepository.class, () -> mock(DomainRegistryRepository.class))
            .withBean(LeaderElection.class, () -> mock(LeaderElection.class));

    @Test
    void shippedYml_isDark_noVaultClient_noReconciler() {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            DomainCaProperties props = ctx.getBean(DomainCaProperties.class);
            assertThat(props.isEnabled()).isFalse();
            assertThat(props.getVaultToken()).isEmpty();
            assertThat(props.getMountPrefix()).isEqualTo("pki-domain-");
            assertThat(ctx).hasSingleBean(DomainCaEffector.class);
            assertThat(ctx).doesNotHaveBean(VaultPkiClient.class);
            assertThat(ctx).doesNotHaveBean(DomainCaReconciler.class);
        });
    }

    @Test
    void enabledWithoutToken_failsTheContext() {
        runner.withPropertyValues("app.domain-registry.ca.enabled=true")
                .run(ctx -> assertThat(ctx).hasFailed()
                        .getFailure().rootCause().hasMessageContaining("no Vault token"));
    }

    @Test
    void enabledWithToken_wiresTheClientAndTheLoop() {
        runner.withPropertyValues("app.domain-registry.ca.enabled=true",
                        "APP_DOMAIN_REGISTRY_CA_VAULT_TOKEN=hvs.wiring-test")
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(VaultPkiClient.class);
                    assertThat(ctx).hasSingleBean(DomainCaReconciler.class);
                    assertThat(ctx.getBean(DomainCaProperties.class).toString())
                            .doesNotContain("hvs.wiring-test");
                });
    }
}
