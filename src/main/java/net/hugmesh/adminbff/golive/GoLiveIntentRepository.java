package net.hugmesh.adminbff.golive;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store facade for {@code go_live_intent} — maps the {@link GoLiveIntentRow}
 * entity to the {@link GoLiveIntent} domain record (mirrors {@link
 * net.hugmesh.adminbff.domainregistry.DomainRegistryRepository}). Every query is
 * UNSCOPED (go-live is cross-domain infra; the controller {@code hasRole('SUPERADMIN')} is
 * the gate). No delete — an intent is WITHDRAWN via a CAS, never removed (audit).
 */
@Repository
public class GoLiveIntentRepository {

    private final GoLiveIntentRowRepository repo;

    public GoLiveIntentRepository(GoLiveIntentRowRepository repo) {
        this.repo = repo;
    }

    /**
     * Insert a new RECORDED intent (DB-generated id, changelog-200 idiom), stamped with the
     * caller-computed monotonic {@code generation}. {@code applied_at}/{@code applied_by} are
     * NEVER supplied — they are the host agent's ack surface (contract: intent only).
     */
    public Mono<GoLiveIntent> insertRecorded(String clusterDomain, String targetState,
                                             String exposureModel, String provider, String note,
                                             String requestedBySubject, long generation) {
        Instant now = Instant.now();
        return repo.insertReturningId(clusterDomain, targetState, exposureModel, provider, note,
                        requestedBySubject, now, now, generation)
                .flatMap(genId -> repo.findById(genId).map(GoLiveIntentRow::toDomain));
    }

    /** Full history, newest first (the wizard's audit view; rows are never deleted). */
    public Flux<GoLiveIntent> findAll() {
        return repo.findAllByOrderByCreatedAtDesc().map(GoLiveIntentRow::toDomain);
    }

    /** The RECORDED (pending) intents, natural-key ordered — the export compile source. */
    public Flux<GoLiveIntent> findRecorded() {
        return repo.findByStatusOrderByClusterDomain(GoLiveIntent.STATUS_RECORDED)
                .map(GoLiveIntentRow::toDomain);
    }

    /** The RECORDED intents targeting one domain (the record-path supersede check). */
    public Flux<GoLiveIntent> findRecordedForDomain(String clusterDomain) {
        return repo.findByClusterDomainAndStatus(clusterDomain, GoLiveIntent.STATUS_RECORDED)
                .map(GoLiveIntentRow::toDomain);
    }

    /** One intent by id, if any. */
    public Mono<GoLiveIntent> findById(String id) {
        return repo.findById(id).map(GoLiveIntentRow::toDomain);
    }

    /** The monotonic table-wide generation floor (0 when empty). */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration();
    }

    /** CAS withdraw {@code recorded -> withdrawn}, stamping the next monotonic generation so
     *  the signed export advances past the removal. 1 = won, 0 = lost / absent / not recorded. */
    public Mono<Long> withdraw(String id, long generation) {
        return repo.withdraw(id, Instant.now(), generation);
    }

    /**
     * HOST-AGENT applied-ack: CAS {@code recorded -> applied}, stamping {@code applied_at}/
     * {@code applied_by}. {@code generation} MUST be the intent row's OWN per-row generation
     * (see {@link GoLiveService#applyAck}) — the WHERE guard binds it together with {@code id}
     * so a stale ack for an already-superseded generation matches zero rows and no-ops rather
     * than touching a different (superseding) row. 1 = applied now, 0 = lost / absent / stale.
     */
    public Mono<Long> markApplied(String id, long generation, String appliedBy) {
        return repo.markApplied(id, Instant.now(), appliedBy, generation);
    }
}
