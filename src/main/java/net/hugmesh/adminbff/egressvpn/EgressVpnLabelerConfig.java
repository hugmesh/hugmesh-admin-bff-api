package net.hugmesh.adminbff.egressvpn;

import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Wires the REAL {@link Fabric8VpnEgressLabeler} + its {@link VpnEgressLabelReconciler} drift
 * sweep — gated behind ONE flag, {@code app.egress-vpn.labeler.enabled} (DEFAULT false).
 * Mirrors {@code BackupStatusReconcilerConfig} EXACTLY (the {@code @ConditionalOnProperty}
 * idiom + the lazy fabric8 {@code KubernetesClient} supplier so a missing in-cluster context
 * never fails BFF boot).
 *
 * <h3>SHIPS DARK (the Noop stays the default, the reconciler bean is ABSENT)</h3>
 * With the flag OFF (the DEFAULT — every dev/test/CI run and every deployment until the
 * egress-vpn optional service is selected) NEITHER bean here is created: the component-scanned
 * {@link NoopVpnEgressLabeler} (gated on the SAME flag's {@code false} branch) is the labeler,
 * and no {@code @Scheduled} sweep exists — no workload/pod is ever labelled and no cluster is
 * dialed. Flipping the flag swaps in the fabric8 labeler AND registers the scheduled sweep.
 * {@code EgressVpnLabelerWiringTest} pins both directions AND the shipped env-binding names.
 *
 * <h3>Single-writer</h3>
 * The reconciler injects the platform-wide {@link LeaderElection} bean ({@code AlwaysLeader}
 * by default; the k8s {@code Lease} when {@code app.access-suspension.lease.enabled=true}) —
 * the SAME single-writer primitive the suspension/games/backup loops use. (The sweep is
 * value-idempotent — converging twice writes the identical labels — so it is safe even
 * without the Lease.)
 */
@Configuration(proxyBeanMethods = false)
public class EgressVpnLabelerConfig {

    private static final Logger log = LoggerFactory.getLogger(EgressVpnLabelerConfig.class);

    /** The REAL labeler — wired ONLY when the flag is true. The Noop is gated on the SAME
     *  flag's {@code false} branch (mutually exclusive), so exactly ONE
     *  {@link VpnEgressLabeler} bean exists in every mode. */
    @Bean
    @ConditionalOnProperty(name = "app.egress-vpn.labeler.enabled", havingValue = "true")
    VpnEgressLabeler fabric8VpnEgressLabeler(
            VpnNodeAssignmentRepository assignments,
            @Value("${app.egress-vpn.labeler.namespace:hugmesh-backend}") String namespace,
            @Value("${app.egress-vpn.labeler.domain-service-slugs:akkoma,tuwunel,coturn}") String slugs) {
        List<String> slugList = Arrays.stream(slugs == null ? new String[0] : slugs.split(","))
                .map(String::trim).filter(s -> !s.isBlank()).collect(Collectors.toList());
        log.info("[egress-vpn] pod labeler ENABLED (namespace={}, domainServiceSlugs={})",
                namespace, slugList);
        return new Fabric8VpnEgressLabeler(() -> new KubernetesClientBuilder().build(),
                assignments, namespace, slugList);
    }

    /** The scheduled drift sweep — registered ONLY when the flag is true, so the
     *  {@code @Scheduled} tick does not even exist by default (the bean is absent). */
    @Bean
    @ConditionalOnProperty(name = "app.egress-vpn.labeler.enabled", havingValue = "true")
    VpnEgressLabelReconciler vpnEgressLabelReconciler(VpnEgressLabeler labeler,
                                                      LeaderElection leader) {
        log.info("[egress-vpn-labeler] drift sweep ENABLED (single-writer via {})",
                leader.label());
        return new VpnEgressLabelReconciler(labeler, leader);
    }
}
