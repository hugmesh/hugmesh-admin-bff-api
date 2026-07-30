package systems.hugmesh.adminbff.backingservices;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code backing_service_mode} (Liquibase changeset 310).
 * The APPEND-ONLY ledger: rows are inserted via {@code save()} on a {@link Persistable}
 * {@link BackingServiceModeRow#forInsert} (app-generated id, {@code isNew=true} forces INSERT —
 * the {@code notification_cursor} / {@code NotificationOutbox} idiom); rows are never mutated or
 * deleted. The {@link BackingServiceModeRepository} facade composes these into its public API.
 *
 * <p>All queries are UNSCOPED — managed backing services are CROSS-DOMAIN infra, gated
 * SUPERADMIN-only at the controller (mirrors {@link
 * systems.hugmesh.adminbff.golive.GoLiveIntentRowRepository}).
 */
public interface BackingServiceModeR2dbcRepository
        extends ReactiveCrudRepository<BackingServiceModeRow, String> {

    /** Full ledger, newest first (the admin console's audit/history view). */
    Flux<BackingServiceModeRow> findAllByOrderByGenerationDesc();

    /** The most-recently-recorded mode row for one service ({@code null} = never recorded =
     *  the self-hosted default). Highest generation wins (the current desired state). */
    Mono<BackingServiceModeRow> findFirstByServiceIdOrderByGenerationDesc(String serviceId);

    /** Monotonic table-wide generation floor: every recorded mode stamps {@code max+1} so the
     *  ledger (and any future signed export) strictly advances (the {@code go_live_intent} /
     *  {@code device_ssh_license} idiom). 0 when empty. */
    @Query("SELECT COALESCE(MAX(generation), 0) FROM backing_service_mode")
    Mono<Long> maxGeneration();
}
