package net.hugmesh.adminbff.egressvpn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The DEFAULT, DARK {@link VpnEgressLabeler}. With the labeler lever off (the cluster-less
 * dev/test/CI default, AND every deployment until the egress-vpn optional service is live) no
 * workload/pod is ever labelled — the interaction NetworkPolicy stays inert exactly as the
 * generator ships it, and assignment mutations behave byte-identically to pre-labeler builds.
 *
 * <p><b>Dark by default.</b> {@link ConditionalOnProperty} (DEFAULT, matchIfMissing) keeps this
 * Noop the bean whenever {@code app.egress-vpn.labeler.enabled} is false/absent, and
 * deterministically yields to the real {@link Fabric8VpnEgressLabeler} (gated on the SAME
 * flag's {@code true} branch in {@link EgressVpnLabelerConfig}) when the flag is on — the
 * {@code NoopBackupEffector} mutually-exclusive-property idiom, so exactly ONE
 * {@link VpnEgressLabeler} registers in every mode.
 */
@Component
@ConditionalOnProperty(name = "app.egress-vpn.labeler.enabled", havingValue = "false",
        matchIfMissing = true)
public class NoopVpnEgressLabeler implements VpnEgressLabeler {

    private static final Logger log = LoggerFactory.getLogger(NoopVpnEgressLabeler.class);

    @Override
    public Mono<Long> reconcile() {
        log.debug("[egress-vpn] SHIPS DARK — no labeler wired; {} not stamped on any workload",
                LABEL_KEY);
        return Mono.just(0L);
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
