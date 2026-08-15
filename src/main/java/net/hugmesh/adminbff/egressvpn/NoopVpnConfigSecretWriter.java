package net.hugmesh.adminbff.egressvpn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The DEFAULT, DARK {@link VpnConfigSecretWriter}. With the delivery lever off (the
 * cluster-less dev/test/CI default, AND every deployment until the generator leg mounts the
 * Secret dir on the nodes), an imported config's bytes are dropped after parse-validation —
 * byte-identical to the pre-delivery behaviour (the node falls back to the key-USB config).
 *
 * <p><b>Dark by default.</b> {@link ConditionalOnProperty} (DEFAULT, matchIfMissing) keeps this
 * Noop the bean whenever {@code app.egress-vpn.secret-delivery.enabled} is false/absent, and
 * deterministically yields to the real {@link Fabric8VpnConfigSecretWriter} (gated on the SAME
 * flag's {@code true} branch in {@link EgressVpnSecretDeliveryConfig}) when the flag is on —
 * the {@code NoopBackupEffector} mutually-exclusive-property idiom, so exactly ONE
 * {@link VpnConfigSecretWriter} registers in every mode.
 *
 * <p>REDACTION: logs only the naming metadata + byte length, NEVER the config body.
 */
@Component
@ConditionalOnProperty(name = "app.egress-vpn.secret-delivery.enabled", havingValue = "false",
        matchIfMissing = true)
public class NoopVpnConfigSecretWriter implements VpnConfigSecretWriter {

    private static final Logger log = LoggerFactory.getLogger(NoopVpnConfigSecretWriter.class);

    @Override
    public Mono<Boolean> write(String secretRef, String domain, String name, String kind,
                               String configBody) {
        log.info("[egress-vpn] SHIPS DARK — no Secret writer wired; config {}/{} kind={} "
                + "({} chars) NOT delivered (secretRef={} stays key-USB/ESO-provisioned)",
                domain, name, kind, configBody == null ? 0 : configBody.length(), secretRef);
        return Mono.just(Boolean.FALSE);
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
