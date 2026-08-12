package net.hugmesh.adminbff.workload;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code workload_console_config} — the master kill-switch rows.
 * The GLOBAL {@link WorkloadConsoleConfig#GLOBAL_DOMAIN} row is seeded OFF by the changelog;
 * a per-domain row is upserted by a superadmin via the config PUT endpoint.
 *
 * <p>Backed by the Spring Data {@link WorkloadConsoleConfigR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link WorkloadConsoleConfigRow} entity to/from the
 * {@link WorkloadConsoleConfig} domain record.
 */
@Repository
public class WorkloadConsoleConfigRepository {

    private final WorkloadConsoleConfigR2dbcRepository repo;

    public WorkloadConsoleConfigRepository(WorkloadConsoleConfigR2dbcRepository repo) {
        this.repo = repo;
    }

    /** The config row for one domain (or the GLOBAL sentinel). Empty when absent. */
    public Mono<WorkloadConsoleConfig> find(String domain) {
        return repo.findByDomain(domain).map(WorkloadConsoleConfigRow::toDomain);
    }

    /** All config rows (superadmin view). */
    public Flux<WorkloadConsoleConfig> listAll() {
        return repo.findByOrderByDomain().map(WorkloadConsoleConfigRow::toDomain);
    }

    /** Upsert (insert-or-update) the master config for one domain. Returns the new row.
     *  generation bumps on every write so streams can detect a config flip. */
    public Mono<WorkloadConsoleConfig> upsert(String domain, boolean adminEnabled,
                                              boolean dangerousTierEnabled, String updatedBy,
                                              long generation) {
        String by = updatedBy == null ? "" : updatedBy;
        return repo.findByDomain(domain)
                .flatMap(existing -> repo.updateByDomain(adminEnabled, dangerousTierEnabled, by,
                                generation, domain)
                        .thenReturn(new WorkloadConsoleConfig(existing.id(), domain, adminEnabled,
                                dangerousTierEnabled, updatedBy, Instant.now(), generation)))
                .switchIfEmpty(Mono.defer(() -> {
                    Instant now = Instant.now();
                    // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT,
                    // changelog 200); RETURNING id hands back the generated string, mapped into
                    // the persisted config with the SAME field order/values as before.
                    return repo.insertReturningId(domain, adminEnabled, dangerousTierEnabled, by,
                                    now, generation)
                            .map(genId -> new WorkloadConsoleConfig(genId, domain, adminEnabled,
                                    dangerousTierEnabled, updatedBy, now, generation));
                }));
    }

    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }
}
