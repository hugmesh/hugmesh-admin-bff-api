package net.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The SHIPS-DARK default {@link DesktopSudoClaimSync}: logs the would-be Casdoor
 * {@code desktop-sudo} role write and reports the row honestly still {@code pending} WITHOUT
 * dialing the IdP. In force whenever {@code app.desktop.sudo.claim-sync.enabled=false} (the
 * DEFAULT). The grant/revoke AUTHORIZATION and the DB desired state run their full sequence
 * against this no-op, so a dev/test/CI run boots clean — and a ships-dark test can assert
 * {@code isReal() == false} structurally. A row left {@code pending} here is the truthful
 * outcome: the claim has NOT reached the IdP.
 */
public class NoopDesktopSudoClaimSync implements DesktopSudoClaimSync {

    private static final Logger log = LoggerFactory.getLogger(NoopDesktopSudoClaimSync.class);

    @Override
    public Mono<String> propagate(DesktopSudoGrant grant) {
        log.info("[desktop-sudo-claim] (noop, SHIPS DARK) would sync desktop-sudo role for "
                        + "subject={} (grant id={} state={}) — propagation stays pending",
                grant.subject(), grant.id(), grant.state());
        return Mono.just(DesktopSudoGrant.PROP_PENDING);
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
