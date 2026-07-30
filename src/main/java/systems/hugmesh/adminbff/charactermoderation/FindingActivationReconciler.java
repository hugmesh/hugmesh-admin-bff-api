package systems.hugmesh.adminbff.charactermoderation;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.lease.LeaderElection;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The moderation→activation reconciler: the FINAL leg that closes the character
 * part/sticker moderation loop. It POLLS federation-api for RESOLVED findings (#71) and
 * PUSHES each outcome to user-bff's character moderation SINK (#87), flipping a PENDING
 * part/sticker row to ACTIVE or REJECTED.
 *
 * <p>It MIRRORS the {@code NotificationReconciler} engine pattern: a {@code @Scheduled}
 * fixed-delay loop, a {@link LeaderElection} single-writer gate (an optimisation, not a
 * correctness requirement — the sink is idempotent), and best-effort never-hard-fail error
 * handling (every error is metered + swallowed so the scheduler thread never dies).
 *
 * <h3>The tick (per surface, oldest-first, strict cursor)</h3>
 * For EACH surface in {@code {character-part, character-sticker}}:
 * <ol>
 *   <li>Read the persisted {@code sinceId} watermark ({@link FindingCursorRepository}).</li>
 *   <li>GET federation {@code /findings/resolved?surface=&sinceId=&limit=} — id ASC,
 *       {@code id>sinceId} strict. A FAILED poll skips the surface this tick (cursor
 *       untouched); an EMPTY page no-ops (cursor untouched).</li>
 *   <li>Process the page in id ASC: map {@code actioned→REJECTED}, {@code dismissed→ACTIVE}
 *       and POST to the {@code parts}|{@code stickers} sink path (by surface) keyed on the
 *       finding's {@code subjectRef}.</li>
 *   <li>Advance the watermark to the LAST id of the CONTIGUOUS prefix of SUCCESSFUL pushes.
 *       The FIRST failure HALTS advancement: its id + everything after stays to be re-polled
 *       next tick (the sink is idempotent, so re-pushing the already-applied earlier rows on
 *       retry is harmless). NEVER advance past a failed push — that would strand a PENDING
 *       row forever.</li>
 * </ol>
 *
 * <h3>never-hard-fail</h3>
 * Each surface is processed independently and its errors are caught + metered; one surface
 * failing never blocks the other, and the tick never throws out of {@code @Scheduled}.
 *
 * <h3>Inert when services absent</h3>
 * Both clients are gated ({@code character-moderation.reconciler.enabled}, default false):
 * the federation read returns an empty page (no call → no advance) and the user-bff push
 * returns FAILED (no call → no advance), so a clientless dev/test/CI run loops harmlessly.
 */
@Service
public class FindingActivationReconciler {

    private static final Logger log = LoggerFactory.getLogger(FindingActivationReconciler.class);

    /** federation surface filter → user-bff sink {kind} path segment, with its cursor key. */
    enum Surface {
        PART("character-part", UserBffCharacterModerationClient.KIND_PARTS,
                FindingCursorRepository.CONSUMER_PART),
        STICKER("character-sticker", UserBffCharacterModerationClient.KIND_STICKERS,
                FindingCursorRepository.CONSUMER_STICKER);

        final String federationSurface;
        final String sinkKind;
        final String cursorConsumer;

        Surface(String federationSurface, String sinkKind, String cursorConsumer) {
            this.federationSurface = federationSurface;
            this.sinkKind = sinkKind;
            this.cursorConsumer = cursorConsumer;
        }
    }

    private final FederationResolvedFindingsClient federation;
    private final UserBffCharacterModerationClient userBff;
    private final FindingCursorRepository cursor;
    private final LeaderElection leader;
    private final int batchSize;

    private final AtomicReference<Instant> lastSuccessAt = new AtomicReference<>(Instant.EPOCH);

    // ── Micrometer counters (never-hard-fail metering) ──────────────────────
    private final Counter applied;     // a part/sticker successfully flipped (or idempotent no-op)
    private final Counter pushFailed;  // a single push failed (halts the surface's cursor, retried)
    private final Counter skipped;     // a malformed/unrecognised finding skipped (halts cursor)
    private final Counter tickErrors;  // an unexpected tick/surface-level error (still swallowed)

    public FindingActivationReconciler(FederationResolvedFindingsClient federation,
                                       UserBffCharacterModerationClient userBff,
                                       FindingCursorRepository cursor,
                                       LeaderElection leader,
                                       MeterRegistry meters,
                                       @Value("${character-moderation.reconcile.batch-size:200}") int batchSize) {
        this.federation = federation;
        this.userBff = userBff;
        this.cursor = cursor;
        this.leader = leader;
        this.batchSize = batchSize;
        this.applied = Counter.builder("character.moderation.reconcile.applied")
                .description("part/sticker rows flipped ACTIVE/REJECTED by the reconciler").register(meters);
        this.pushFailed = Counter.builder("character.moderation.reconcile.push_failed")
                .description("moderation pushes that failed (halt the surface cursor, retry next tick)").register(meters);
        this.skipped = Counter.builder("character.moderation.reconcile.skipped")
                .description("malformed/unrecognised resolved findings skipped (halt the surface cursor)").register(meters);
        this.tickErrors = Counter.builder("character.moderation.reconcile.tick_errors")
                .description("unexpected reconcile errors (swallowed; tick never hard-fails)").register(meters);
    }

    public Instant lastSuccessAt() {
        return lastSuccessAt.get();
    }

    @Scheduled(
            fixedDelayString = "${character-moderation.reconcile.interval-ms:30000}",
            initialDelayString = "${character-moderation.reconcile.initial-delay-ms:20000}")
    public void runTick() {
        runOnce()
                .doOnSuccess(v -> lastSuccessAt.set(Instant.now()))
                // Belt-and-braces: runOnce already swallows, but a @Scheduled method must
                // never let anything escape — meter + drop.
                .onErrorResume(e -> {
                    tickErrors.increment();
                    log.warn("[char-mod-reconcile] tick error (swallowed): {}", e.toString());
                    return Mono.empty();
                })
                .subscribe();
    }

    /**
     * One reconcile pass over BOTH surfaces. Never errors (the chain is fully swallowed so
     * the scheduler never sees a failure). Skips entirely when not the leader.
     */
    public Mono<Void> runOnce() {
        if (!leader.isLeader()) {
            log.debug("[char-mod-reconcile] not leader ({}) — skipping tick", leader.label());
            return Mono.empty();
        }
        // Process the two surfaces sequentially; each is independently swallowed so one
        // failing never blocks the other.
        return Flux.fromArray(Surface.values())
                .concatMap(this::reconcileSurface)
                .then()
                .onErrorResume(e -> {
                    tickErrors.increment();
                    log.warn("[char-mod-reconcile] tick failed (will retry next tick): {}", e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Poll + drain ONE surface. Reads the cursor, fetches the resolved page, processes it,
     * and advances the cursor past the contiguous-success prefix. Never errors: a failed
     * poll / push is metered + swallowed and leaves the cursor where it is (retry next tick).
     */
    Mono<Void> reconcileSurface(Surface surface) {
        return cursor.find(surface.cursorConsumer)
                .defaultIfEmpty(0L) // cold start → sinceId 0 (strict id>0)
                .flatMap(sinceId -> federation
                        .fetchResolved(surface.federationSurface, sinceId, batchSize)
                        .flatMap(page -> drain(surface, page)))
                .onErrorResume(e -> {
                    // A failed federation poll (or any unexpected surface error): skip this
                    // surface this tick, DO NOT advance the cursor — retried next tick.
                    pushFailed.increment();
                    log.warn("[char-mod-reconcile] surface {} poll/drain failed (cursor unchanged, "
                            + "retry next tick): {}", surface.federationSurface, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * Process a fetched page in id ASC, pushing each finding to the sink, tracking the LAST
     * id of the contiguous prefix of SUCCESSFUL pushes, and advancing the cursor to it (only
     * if that prefix is non-empty). Stops examining the page at the first failure (HALT) —
     * the remaining ids are deliberately left for the next poll.
     */
    private Mono<Void> drain(Surface surface, List<ResolvedFindingDto> page) {
        if (page.isEmpty()) {
            log.debug("[char-mod-reconcile] surface {} empty page — nothing to do",
                    surface.federationSurface);
            return Mono.empty();
        }
        // advanceTo = highest id of the contiguous success prefix; halted = first failure seen.
        AtomicLong advanceTo = new AtomicLong(Long.MIN_VALUE);
        AtomicReference<Boolean> halted = new AtomicReference<>(Boolean.FALSE);
        return Flux.fromIterable(page)
                // concatMap = strictly sequential (id ASC) so the contiguous-prefix invariant
                // holds; takeUntil short-circuits the rest of the page after the first failure.
                .concatMap(finding -> pushOne(surface, finding, advanceTo, halted))
                .takeUntil(Boolean.TRUE::equals) // stop after a finding that HALTED the prefix
                .then(Mono.defer(() -> {
                    long to = advanceTo.get();
                    if (to == Long.MIN_VALUE) {
                        // No contiguous success (the very first finding failed) — leave the
                        // cursor untouched so the whole page is re-polled next tick.
                        return Mono.empty();
                    }
                    return cursor.advance(surface.cursorConsumer, to);
                }));
    }

    /**
     * Push ONE finding. Returns a never-erroring {@code Mono<Boolean>} that emits TRUE iff
     * this finding HALTED the contiguous prefix (a failed push or a malformed finding) so
     * {@code takeUntil} stops the page. On success it records the id as the new prefix tip.
     */
    private Mono<Boolean> pushOne(Surface surface, ResolvedFindingDto finding,
                                  AtomicLong advanceTo, AtomicReference<Boolean> halted) {
        if (Boolean.TRUE.equals(halted.get())) {
            // Defensive: takeUntil should already have stopped us; never push past a halt.
            return Mono.just(Boolean.TRUE);
        }
        if (!finding.isPushable()) {
            // A malformed / unrecognised-status finding: we cannot safely flip on it, and we
            // must NOT skip past it (that would strand the affected PENDING row). HALT the
            // prefix here — the cursor stops before this id; an operator can resolve the bad
            // finding upstream. (Federation returns only actioned/dismissed, so this is a
            // contract-violation guard, not an expected path.)
            skipped.increment();
            halted.set(Boolean.TRUE);
            log.warn("[char-mod-reconcile] surface {} finding {} not pushable "
                    + "(status={}, subjectRef={}) — HALT cursor before it",
                    surface.federationSurface, finding.id(), finding.status(), finding.subjectRef());
            return Mono.just(Boolean.TRUE);
        }
        String status = mapStatus(finding.status());
        return userBff.applyModeration(surface.sinkKind, finding.subjectRef(), status,
                        finding.id(), finding.reviewer())
                .map(outcome -> {
                    if (outcome == UserBffCharacterModerationClient.Outcome.APPLIED) {
                        applied.increment();
                        // Extend the contiguous-success prefix tip to this id (page is id ASC).
                        advanceTo.set(finding.id());
                        return Boolean.FALSE; // continue the page
                    }
                    // FAILED push: HALT — do not advance past this id; re-polled next tick.
                    pushFailed.increment();
                    halted.set(Boolean.TRUE);
                    return Boolean.TRUE;
                })
                .onErrorResume(e -> {
                    // Defence-in-depth: an unexpected per-finding error must HALT (never skip).
                    pushFailed.increment();
                    halted.set(Boolean.TRUE);
                    log.warn("[char-mod-reconcile] surface {} finding {} push errored "
                            + "(HALT cursor): {}", surface.federationSurface, finding.id(), e.toString());
                    return Mono.just(Boolean.TRUE);
                });
    }

    /** federation finding status → user-bff moderation status:
     *  {@code actioned}→{@code REJECTED} (content removed), {@code dismissed}→{@code ACTIVE}
     *  (report rejected, content stands). */
    static String mapStatus(String findingStatus) {
        return switch (findingStatus) {
            case ResolvedFindingDto.STATUS_ACTIONED -> "REJECTED";
            case ResolvedFindingDto.STATUS_DISMISSED -> "ACTIVE";
            default -> throw new IllegalArgumentException(
                    "unmappable federation finding status: " + findingStatus);
        };
    }
}
