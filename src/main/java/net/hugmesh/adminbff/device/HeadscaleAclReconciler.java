package net.hugmesh.adminbff.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.ExportModels.SignedExport;
import net.hugmesh.adminbff.device.HeadscalePolicyClient.PushOutcome;
import net.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The LEADER-GATED, IDEMPOTENT, FAIL-CLOSED reconcile loop that pushes the signed
 * device-license export into headscale as the mesh ACL policy (Layer-A). It is the WRITE
 * counterpart to the read-only enrolled-node enumeration: every tick it
 * <ol>
 *   <li>builds the SIGNED per-mesh export ({@code DeviceRegistryExportService.exportMesh}),</li>
 *   <li>compiles its body into a headscale ACL policy ({@link HeadscaleAclCompiler}),</li>
 *   <li>pushes it via {@link HeadscalePolicyClient#setPolicy} ONLY IF it changed since the last
 *       successful push (idempotency), keeping the last-good text on any failure.</li>
 * </ol>
 *
 * <p>Clones the {@code GameInstanceReconciler} idiom EXACTLY: a {@code @Scheduled} tick, the
 * {@link LeaderElection} single-writer gate (headscale holds ONE policy — two replicas pushing
 * would flap it), {@code runOnce()} returning a {@link Mono}, and best-effort error-swallow so a
 * tick failure retries next tick and never kills the schedule.
 *
 * <h3>Idempotency + keep-last-good (fail-closed)</h3>
 * The compiled policy is pure/deterministic for a stable export, so an unchanged registry yields
 * an unchanged policy yields a SKIPPED push. {@link #lastPushedPolicy} caches the
 * last-SUCCESSFULLY-applied text; on a degraded push it is NOT advanced, so the next tick re-tries
 * the same desired text — and crucially a transient headscale failure NEVER clears or widens the
 * live policy (the loop only ever PUTs a freshly-compiled, non-empty allow-set; it never DELETEs).
 * On first boot {@link #getPolicy()} is consulted so a policy headscale already holds that equals
 * the desired text is adopted without a redundant PUT.
 *
 * <h3>Ships DARK</h3>
 * With {@code app.registry.headscale-acl.enabled=false} (default) the injected
 * {@link HeadscalePolicyClient} is the {@link NoopHeadscalePolicyClient}: the loop still compiles
 * every tick and maintains the change-detection state, but {@code setPolicy} is a logged no-op
 * ({@link PushOutcome#stubbed}) — zero mesh mutation. So the FULL reconcile contract (compile,
 * diff, skip-on-no-change, keep-last-good-on-failure) is exercised with no live headscale.
 */
public class HeadscaleAclReconciler {

    private static final Logger log = LoggerFactory.getLogger(HeadscaleAclReconciler.class);

    private final DeviceRegistryExportService exportService;
    private final HeadscaleAclCompiler compiler;
    private final HeadscalePolicyClient policyClient;
    private final LeaderElection leader;
    private final String meshId;

    /** The last policy text SUCCESSFULLY applied to (or confirmed present in) headscale. Null
     *  until the first successful apply/adoption — drives the skip-on-no-change idempotency and
     *  the keep-last-good fail-closed behaviour. */
    private final AtomicReference<String> lastPushedPolicy = new AtomicReference<>(null);

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    public HeadscaleAclReconciler(DeviceRegistryExportService exportService,
                                  HeadscaleAclCompiler compiler,
                                  HeadscalePolicyClient policyClient,
                                  LeaderElection leader,
                                  String meshId) {
        this.exportService = exportService;
        this.compiler = compiler;
        this.policyClient = policyClient;
        this.leader = leader;
        this.meshId = meshId;
    }

    /** Visible for tests: the last text successfully applied/adopted (null until first). */
    String lastPushedPolicy() {
        return lastPushedPolicy.get();
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${app.registry.headscale-acl.reconcile-interval-ms:60000}",
            initialDelayString = "${app.registry.headscale-acl.reconcile-initial-delay-ms:30000}")
    public void runTick() {
        runOnce()
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /**
     * One reconcile pass: compile the desired policy and push it iff changed. Skips entirely
     * when not the leader (single-writer). Errors are swallowed (retry next tick) so the
     * scheduled loop never dies. Returns the {@link PushOutcome} (APPLIED / STUBBED / DEGRADED)
     * or a synthetic SKIPPED-equivalent (APPLIED with no change) for assertion in tests.
     */
    public Mono<PushOutcome> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[headscale-acl] not leader ({}) — skipping tick", leader.label());
            return Mono.just(PushOutcome.stubbed());
        }
        return exportService.exportMesh(meshId)
                .map(this::compileChecked)
                .flatMap(this::pushIfChanged)
                .doOnSuccess(o -> {
                    if (o.isApplied()) {
                        lastSuccessAt.set(Instant.now());
                    }
                })
                .onErrorResume(e -> {
                    log.warn("[headscale-acl] reconcile tick failed (keeping last-good, retry next tick): {}",
                            e.toString());
                    return Mono.just(PushOutcome.degraded(e.toString()));
                });
    }

    /** Compile the export body; an empty/whitespace policy is treated as a no-push guard (the
     *  compiler never emits blank, but defend anyway — never push an empty body). */
    private String compileChecked(SignedExport export) {
        String policy = compiler.compile(export.body());
        return policy == null ? "" : policy;
    }

    /**
     * Push the desired policy iff it differs from the last successfully-applied text. On first
     * tick, consult headscale's current policy: if it already equals the desired text, adopt it
     * (no redundant PUT). Refuse to push an empty body (fail-closed). Keep last-good on a
     * degraded push.
     */
    private Mono<PushOutcome> pushIfChanged(String desired) {
        if (desired.isBlank()) {
            log.warn("[headscale-acl] compiled policy is empty — refusing to push (fail-closed, keep last-good)");
            return Mono.just(PushOutcome.degraded("empty compiled policy"));
        }
        String last = lastPushedPolicy.get();
        if (desired.equals(last)) {
            log.debug("[headscale-acl] desired policy unchanged since last apply — skipping PUT (idempotent)");
            return Mono.just(PushOutcome.applied());
        }
        // First reconcile (no last-good yet): adopt headscale's current policy if it already
        // matches, so we don't PUT a policy it already holds. Otherwise (and on every subsequent
        // change) PUT the desired text.
        if (last == null) {
            return policyClient.getPolicy()
                    .defaultIfEmpty("")
                    .flatMap(current -> {
                        if (desired.equals(current)) {
                            lastPushedPolicy.set(desired);
                            log.info("[headscale-acl] live policy already matches desired (gen-stable) — adopted, no PUT");
                            return Mono.just(PushOutcome.applied());
                        }
                        return doPush(desired);
                    });
        }
        return doPush(desired);
    }

    /** Issue the push; advance last-good ONLY on APPLIED/STUBBED (a disabled Noop is a benign
     *  no-op that still advances the change-detection baseline so the loop is quiet); a DEGRADED
     *  push keeps last-good so the next tick retries the SAME desired text (fail-closed). */
    private Mono<PushOutcome> doPush(String desired) {
        return policyClient.setPolicy(desired)
                // Advance the last-good baseline on success; log a warning on degraded.
                .map(outcome -> recordPushOutcome(outcome, desired));
    }

    /** Log the push outcome and advance the last-good baseline on APPLIED or STUBBED. */
    private PushOutcome recordPushOutcome(PushOutcome outcome, String desired) {
        if (outcome.isApplied() || outcome.isStubbed()) {
            lastPushedPolicy.set(desired);
            if (outcome.isApplied()) {
                log.info("[headscale-acl] applied new mesh policy for '{}' ({} bytes)",
                        meshId, desired.length());
            }
        } else {
            log.warn("[headscale-acl] policy push degraded ({}) — keeping last-good, retry next tick",
                    outcome.detail());
        }
        return outcome;
    }
}
