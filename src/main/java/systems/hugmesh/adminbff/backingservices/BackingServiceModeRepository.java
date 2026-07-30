package systems.hugmesh.adminbff.backingservices;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Reactive (R2DBC) store facade for {@code backing_service_mode} — maps the
 * {@link BackingServiceModeRow} entity to the {@link BackingServiceMode} domain record
 * (mirrors {@link systems.hugmesh.adminbff.golive.GoLiveIntentRepository}). Every query is
 * UNSCOPED (managed backing services are cross-domain infra; the controller
 * {@code hasRole('SUPERADMIN')} is the gate). APPEND-ONLY — a mode change is a new row, never
 * an update or delete (audit).
 */
@Repository
public class BackingServiceModeRepository {

    private final BackingServiceModeR2dbcRepository repo;

    public BackingServiceModeRepository(BackingServiceModeR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Record a new mode intent (app-generated UUID, {@link BackingServiceModeRow#forInsert} +
     * {@code save} — the Persistable-{@code isNew} INSERT idiom), stamped with the
     * caller-computed monotonic {@code generation}. Returns the persisted domain record.
     */
    public Mono<BackingServiceMode> insertRecorded(String serviceId, String mode, String endpoint,
                                                   String credsRef, String requestedBySubject,
                                                   long generation) {
        BackingServiceModeRow row = BackingServiceModeRow.forInsert(
                UUID.randomUUID().toString(), serviceId, mode, endpoint, credsRef,
                requestedBySubject, generation);
        return repo.save(row).map(BackingServiceModeRow::toDomain);
    }

    /** Full ledger, newest first (the audit/history view; rows are never deleted). */
    public Flux<BackingServiceMode> history() {
        return repo.findAllByOrderByGenerationDesc().map(BackingServiceModeRow::toDomain);
    }

    /** The CURRENT (highest-generation) recorded mode for one service, or empty (never
     *  recorded = the self-hosted default). */
    public Mono<BackingServiceMode> currentMode(String serviceId) {
        return repo.findFirstByServiceIdOrderByGenerationDesc(serviceId)
                .map(BackingServiceModeRow::toDomain);
    }

    /** The CURRENT recorded mode per service id (the highest-generation row for each), keyed by
     *  {@code serviceId}. Derived from one newest-first ledger scan (first row seen per id wins),
     *  so the read is a single query. Services with no recorded row are ABSENT from the map (they
     *  are self-hosted by default — the caller fills that in from the catalog). */
    public Mono<Map<String, BackingServiceMode>> currentModes() {
        return repo.findAllByOrderByGenerationDesc()
                .collect(LinkedHashMap::new, (Map<String, BackingServiceMode> acc, BackingServiceModeRow r) -> {
                    // Newest-first: the FIRST row seen for a service_id is its current desired state.
                    acc.putIfAbsent(r.serviceId(), r.toDomain());
                });
    }

    /** The monotonic table-wide generation floor (0 when empty). */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration();
    }
}
