package net.hugmesh.adminbff.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The cluster-less default {@link HeadscalePolicyClient}: logs the would-be policy push and
 * reports {@link PushOutcome#stubbed()} WITHOUT touching a headscale control node. Wired
 * whenever the real WebClient client is not enabled ({@code app.registry.headscale-acl.enabled=false},
 * the default) — CI, dev, a single-stick deployment with no headscale, every existing test.
 *
 * <p>Mirrors {@link NoopHeadscalePolicyClient}'s siblings {@code NoopInstanceConfigMapWriter} /
 * {@code NoopBackupEffector}: the compile + reconcile contract (the {@link HeadscaleAclReconciler}
 * tick — compile the desired policy, keep last-good, skip on no-change) is fully exercised; only
 * the actual {@code PUT /api/v1/policy} is a no-op. {@link #getPolicy()} returns empty (a
 * disabled client knows nothing of the live policy) so the reconciler treats current-policy as
 * unknown and the compile path still runs.
 */
public class NoopHeadscalePolicyClient implements HeadscalePolicyClient {

    private static final Logger log = LoggerFactory.getLogger(NoopHeadscalePolicyClient.class);

    @Override
    public Mono<String> getPolicy() {
        return Mono.empty();
    }

    @Override
    public Mono<PushOutcome> setPolicy(String policyJson) {
        log.debug("[headscale-acl] (noop) would PUT /api/v1/policy ({} bytes) — disabled, no mesh mutation",
                policyJson == null ? 0 : policyJson.length());
        return Mono.just(PushOutcome.stubbed());
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
