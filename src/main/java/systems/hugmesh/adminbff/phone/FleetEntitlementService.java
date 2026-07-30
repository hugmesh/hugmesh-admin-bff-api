package systems.hugmesh.adminbff.phone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * The FLEET-ADMIN SUBSCRIPTION gate (changeset 306) — the entitlement seam the public
 * {@code /bff/admin/phone-fleet/**} owner surface consults, plus the SUPERADMIN admin surface
 * that manages it.
 *
 * <h3>The gate</h3>
 * {@link #isEntitled(String)} is the ONE question the fleet-admin controller asks:
 * {@code subject} has an entitlement row that is ACTIVE and unexpired. FAIL-CLOSED — a null /
 * blank subject, a missing row, an inactive row, or an expired row all yield {@code false}
 * (the expiry is checked against the DB clock in the count query). A SUPERADMIN is exempt
 * (the controller never calls this for a genuine superadmin authority).
 *
 * <h3>Admin surface (SUPERADMIN + step-up)</h3>
 * {@link #upsert} is a portable UPDATE-then-INSERT (the natural {@code subject} PK cannot use
 * Spring Data's insert/update inference); {@link #delete} revokes; {@link #list} enumerates.
 */
@Service
public class FleetEntitlementService {

    private static final Logger log = LoggerFactory.getLogger(FleetEntitlementService.class);

    private final FleetEntitlementRowRepository repo;

    public FleetEntitlementService(FleetEntitlementRowRepository repo) {
        this.repo = repo;
    }

    /**
     * TRUE iff {@code subject} holds an ACTIVE, unexpired fleet entitlement. Fail-closed on a
     * null/blank subject (never queries) and on a missing row / inactive / expired (the count
     * is 0). The expiry comparison uses the DB clock, never the JVM clock.
     */
    public Mono<Boolean> isEntitled(String subject) {
        if (subject == null || subject.isBlank()) {
            return Mono.just(false);
        }
        return repo.countEntitled(subject).map(n -> n != null && n > 0).defaultIfEmpty(false);
    }

    /**
     * Upsert an entitlement for {@code subject}. Tries the UPDATE first; if no row existed
     * (rows-updated 0) it INSERTs, folding a concurrent-insert DuplicateKey back into an
     * UPDATE (the loser of the first-write race lands the same values). Returns the resulting
     * row.
     */
    public Mono<FleetEntitlement> upsert(String subject, boolean active, Integer seats,
                                         Instant expiresAt) {
        Mono<Void> write = repo.updateEntitlement(subject, active, seats, expiresAt)
                .flatMap(updated -> updated > 0
                        ? Mono.<Void>empty()
                        : repo.insertEntitlement(subject, active, seats, expiresAt)
                                .onErrorResume(DuplicateKeyException.class, race ->
                                        repo.updateEntitlement(subject, active, seats, expiresAt))
                                .then())
                .then();
        return write.then(Mono.defer(() -> {
            log.info("[fleet-entitlement] upsert subject active={} (by superadmin)", active);
            return find(subject);
        }));
    }

    /** Revoke an entitlement outright; returns rows-deleted (0 when the subject had none). */
    public Mono<Long> delete(String subject) {
        return repo.deleteEntitlement(subject)
                .doOnNext(n -> log.info("[fleet-entitlement] delete subject rows={}", n));
    }

    /** All entitlements, subject-ordered (the superadmin list). */
    public Flux<FleetEntitlement> list() {
        return repo.findAllByOrderBySubjectAsc().map(FleetEntitlementRow::toDomain);
    }

    /** One entitlement by subject, empty when absent. */
    public Mono<FleetEntitlement> find(String subject) {
        return repo.findById(subject).map(FleetEntitlementRow::toDomain);
    }
}
