package net.hugmesh.adminbff.capability;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code domain_capability} — the per-(domain, capability) gate
 * rows. The GLOBAL {@link DomainCapability#GLOBAL_DOMAIN} row is seeded OFF by the
 * changelog; a per-domain row is upserted by a SUPERADMIN (the {@code granted} key) or a
 * domain ADMIN (the {@code enabled} key) via {@link DomainCapabilityService}.
 *
 * <p>Backed by the Spring Data {@link DomainCapabilityR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DomainCapabilityRow} entity to/from the
 * {@link DomainCapability} domain record. CLONES
 * {@code WorkloadConsoleConfigRepository} verbatim, keyed on the composite
 * (domain, capability) instead of domain alone.
 */
@Repository
public class DomainCapabilityRepository {

    private final DomainCapabilityR2dbcRepository repo;

    public DomainCapabilityRepository(DomainCapabilityR2dbcRepository repo) {
        this.repo = repo;
    }

    /** The gate row for one (domain, capability) pair (or the GLOBAL sentinel). Empty
     *  when absent. */
    public Mono<DomainCapability> find(String domain, String capability) {
        return repo.findByDomainAndCapability(domain, capability).map(DomainCapabilityRow::toDomain);
    }

    /** All gate rows for one domain — the domain-scoped ADMIN read. */
    public Flux<DomainCapability> listForDomain(String domain) {
        return repo.findByDomainOrderByCapability(domain).map(DomainCapabilityRow::toDomain);
    }

    /** All gate rows (superadmin view). */
    public Flux<DomainCapability> listAll() {
        return repo.findByOrderByDomainAscCapabilityAsc().map(DomainCapabilityRow::toDomain);
    }

    /** Upsert (insert-or-update) the gate row for one (domain, capability) pair. Returns
     *  the new row. generation bumps on every write so a caller can detect a config flip
     *  (same monotonic-counter idiom as {@code WorkloadConsoleConfigRepository#upsert}). */
    public Mono<DomainCapability> upsert(String domain, String capability, boolean granted,
                                         boolean enabled, String updatedBy, long generation) {
        String by = updatedBy == null ? "" : updatedBy;
        return repo.findByDomainAndCapability(domain, capability)
                .flatMap(existing -> repo.updateByDomainAndCapability(granted, enabled, by,
                                generation, domain, capability)
                        .thenReturn(new DomainCapability(existing.id(), domain, capability,
                                granted, enabled, updatedBy, Instant.now(), generation)))
                .switchIfEmpty(Mono.defer(() -> {
                    Instant now = Instant.now();
                    // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT,
                    // changeset 303); RETURNING id hands back the generated string, mapped into
                    // the persisted gate with the SAME field order/values as before.
                    return repo.insertReturningId(domain, capability, granted, enabled, by, now,
                                    generation)
                            .map(genId -> new DomainCapability(genId, domain, capability, granted,
                                    enabled, updatedBy, now, generation));
                }));
    }

    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }
}
