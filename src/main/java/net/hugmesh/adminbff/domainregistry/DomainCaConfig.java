package net.hugmesh.adminbff.domainregistry;

import net.hugmesh.adminbff.config.OutboundMtlsClient;
import net.hugmesh.adminbff.lease.LeaderElection;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the per-domain CA effector (hugmesh-admin-bff-api#99). One flag,
 * {@code app.domain-registry.ca.enabled} (default false):
 * <ul>
 *   <li>false (DEFAULT) — no {@link VaultPkiClient} and no {@link DomainCaReconciler} exist;
 *       the {@link DomainCaEffector} bean is present but answers DISABLED and touches nothing;</li>
 *   <li>true — the Vault client is built on the outbound cluster-CA-trusting connector
 *       ({@link OutboundMtlsClient}, as the ArgoCD effector is) and the leader-gated reconcile
 *       loop is scheduled. A blank token or Vault address fails the context instead of
 *       producing a loop that 403s forever.</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({DomainCaProperties.class, OutboundMtlsClient.class})
public class DomainCaConfig {

    static final String ENABLED = "app.domain-registry.ca.enabled";

    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "true")
    VaultPkiClient domainCaVaultPkiClient(DomainCaProperties props, OutboundMtlsClient mtls) {
        requireConfigured(props);
        return new VaultPkiClient(props.getVaultAddr().trim(), props.getVaultToken().trim(),
                VaultPkiClient.RootSpec.of(props), props.getTimeoutMs(), mtls.httpClient());
    }

    @Bean
    DomainCaEffector domainCaEffector(DomainRegistryRepository repo,
                                      ObjectProvider<VaultPkiClient> vault,
                                      DomainCaProperties props) {
        return new DomainCaEffector(repo, vault.getIfAvailable(), props);
    }

    @Bean
    @ConditionalOnProperty(name = ENABLED, havingValue = "true")
    DomainCaReconciler domainCaReconciler(DomainCaEffector effector, LeaderElection leader) {
        return new DomainCaReconciler(effector, leader);
    }

    /**
     * The enabled path's boot gate: a missing token or address would otherwise surface only as
     * a WARN per domain per tick. Never echoes the token value.
     */
    static void requireConfigured(DomainCaProperties props) {
        if (props.getVaultAddr() == null || props.getVaultAddr().isBlank()) {
            throw new IllegalStateException("[domain-ca] " + ENABLED + "=true but "
                    + "app.domain-registry.ca.vault-addr is empty — refusing to wire the CA effector");
        }
        if (props.getVaultToken() == null || props.getVaultToken().isBlank()) {
            throw new IllegalStateException("[domain-ca] " + ENABLED + "=true but no Vault token "
                    + "is configured (app.domain-registry.ca.vault-token / "
                    + "APP_DOMAIN_REGISTRY_CA_VAULT_TOKEN) — refusing to wire the CA effector");
        }
        if (props.getMountPrefix() == null || props.getMountPrefix().isBlank()) {
            throw new IllegalStateException("[domain-ca] app.domain-registry.ca.mount-prefix is "
                    + "empty — a bare slug would put a domain's PKI mount at the root of Vault's "
                    + "mount table");
        }
    }
}
