package net.hugmesh.adminbff.phone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The cluster-less default {@link PhoneLockLeg} for the headscale ACL phone-deny: logs the
 * would-be deny and reports {@link LegOutcome#disabled} WITHOUT touching headscale. Wired
 * whenever the real leg is not enabled ({@code app.phone-lock.mesh-deny.enabled=false}, the
 * default).
 *
 * <p>Mirrors {@link net.hugmesh.adminbff.device.NoopHeadscalePolicyClient} — the mesh
 * cut is the deferred, infra-gated half; the aggregate enforcement still records the
 * authoritative lock and degrades cleanly with no live headscale.
 */
public class NoopPhoneMeshDenyClient implements PhoneLockLeg {

    private static final Logger log = LoggerFactory.getLogger(NoopPhoneMeshDenyClient.class);

    static final String LEG = "mesh-deny";

    @Override
    public String name() {
        return LEG;
    }

    @Override
    public Mono<LegOutcome> lock(PhoneDevice device) {
        return disabled("deny");
    }

    @Override
    public Mono<LegOutcome> unlock(PhoneDevice device) {
        return disabled("re-allow");
    }

    private Mono<LegOutcome> disabled(String verb) {
        log.debug("[phone-lock] (noop) would {} tailscale host in headscale ACL — mesh-deny leg disabled, no push",
                verb);
        return Mono.just(LegOutcome.disabled("mesh-deny leg disabled (app.phone-lock.mesh-deny.enabled=false)"));
    }
}
