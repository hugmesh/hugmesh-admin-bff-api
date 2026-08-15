package net.hugmesh.adminbff.desktop;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

/**
 * Reactive (R2DBC) store for {@code desktop_sudo_grant} — the SSO-enforced sudo grants.
 * App-generated UUID ids, the verified {@code scope == null || scope.scoped() ?
 * WHERE domain=:domain : unscoped} read branch, {@code findActive}-before-insert idempotency
 * (the PG partial-unique WHERE active is the Postgres backstop; the H2 test store relies on the
 * service guard), a CAS {@code active -> revoked} that NEVER deletes (the row is the audit
 * trail), and a monotonic {@code generation} bumped on every mutate.
 *
 * <p>Backed by the Spring Data {@link DesktopSudoGrantR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DesktopSudoGrantRow} entity to/from the
 * {@link DesktopSudoGrant} domain record.
 *
 * <p>The entitlement read ({@link #activeForSubjectAndDevice} / {@link #activeForDevice} /
 * {@link #listActiveAll}) is UNSCOPED — it is what the IdP/desktop consults to mint the
 * {@code desktop-sudo} claim; a revoked grant is absent from it, so revocation removes the
 * claim.
 */
@Repository
public class DesktopSudoGrantRepository {

    private final DesktopSudoGrantR2dbcRepository repo;

    public DesktopSudoGrantRepository(DesktopSudoGrantR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── grant (findActive-then-insert idempotency) ──────────────────────────────

    /** The active grant for (subject, deviceId), if any — the idempotency check. UNSCOPED. */
    public Mono<DesktopSudoGrant> findActive(String subject, String deviceId) {
        return repo.findBySubjectAndDeviceIdAndState(subject, deviceId, DesktopSudoGrant.STATE_ACTIVE)
                .map(DesktopSudoGrantRow::toDomain);
    }

    /** Insert a new ACTIVE grant (app-generated id) at the given monotonic generation,
     *  stamped with the device's residency {@code domain}. Returns it. */
    public Mono<DesktopSudoGrant> insertActive(String subject, String deviceId, String domain,
                                               String grantedBy, long generation) {
        Instant grantedAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set revoked_at/revoked_by (default NULL); RETURNING id hands back
        // the generated string, mapped into the persisted grant with the SAME field order/values.
        return repo.insertReturningId(subject, deviceId, DesktopSudoGrant.STATE_ACTIVE, grantedBy,
                        grantedAt, domain, DesktopSudoGrant.PROP_PENDING, generation)
                .map(genId -> new DesktopSudoGrant(genId, subject, deviceId,
                        DesktopSudoGrant.STATE_ACTIVE, grantedBy, grantedAt, null, null, domain,
                        DesktopSudoGrant.PROP_PENDING, generation));
    }

    // ── read (admin surface, scoped) ────────────────────────────────────────────

    /** ALL grants VISIBLE to the given tenant scope — the ADMIN read surface (own brand;
     *  SUPERADMIN all). */
    public Flux<DesktopSudoGrant> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderBySubjectAscGrantedAtDesc(domain)
                    .map(DesktopSudoGrantRow::toDomain);
        }
        return repo.findByOrderByDomainAscSubjectAscGrantedAtDesc()
                .map(DesktopSudoGrantRow::toDomain);
    }

    /** A single row by id (UNSCOPED — for fetching state after a CAS). */
    public Mono<DesktopSudoGrant> findById(String id) {
        return repo.findById(id).map(DesktopSudoGrantRow::toDomain);
    }

    // ── entitlement read (UNSCOPED — the IdP/desktop claim source) ──────────────

    /** The active grant for (subject, deviceId) — the entitlement the IdP/desktop reads to
     *  decide whether to mint the sudo claim. Empty = NO sudo (default-none / revoked). */
    public Mono<DesktopSudoGrant> activeForSubjectAndDevice(String subject, String deviceId) {
        return findActive(subject, deviceId);
    }

    /** All active grants on one device (the per-device entitlement view). UNSCOPED. */
    public Flux<DesktopSudoGrant> activeForDevice(String deviceId) {
        return repo.findByDeviceIdAndStateOrderBySubject(deviceId, DesktopSudoGrant.STATE_ACTIVE)
                .map(DesktopSudoGrantRow::toDomain);
    }

    /** ALL active grants (every brand). UNSCOPED — the full entitlement working set. */
    public Flux<DesktopSudoGrant> listActiveAll() {
        return repo.findByStateOrderBySubject(DesktopSudoGrant.STATE_ACTIVE)
                .map(DesktopSudoGrantRow::toDomain);
    }

    /** The current maximum {@code generation} across ALL grant rows. Returns 0 when empty. */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    // ── revoke (CAS, audited, generation bump) ──────────────────────────────────

    /**
     * Compare-and-swap {@code active -> revoked} for one row id at a NEW generation,
     * guarded on the current state so only ONE writer wins the transition (rows-updated:
     * 1 = this caller won + audit stamped, 0 = already revoked / absent / out of scope).
     * The row is NEVER deleted — {@code revoked_at}/{@code revoked_by} stamp the audit.
     */
    public Mono<Long> revoke(String id, String revokedBy, long newGeneration, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.revokeScoped(id, revokedBy, newGeneration, domain);
        }
        return repo.revokeAll(id, revokedBy, newGeneration);
    }

    /** Record the push-with-ack propagation outcome for a row [FIX-REVOKE]. UNSCOPED. */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }

    // ── claim propagation (the Casdoor desktop-sudo role sync working set) ──────

    /** True iff {@code subject} holds ANY active grant (any device) — the Casdoor
     *  role-membership floor: a revoke drops the {@code desktop-sudo} membership only when
     *  this turns false. UNSCOPED. */
    public Mono<Boolean> hasActiveForSubject(String subject) {
        return repo.findBySubjectAndState(subject, DesktopSudoGrant.STATE_ACTIVE).hasElements();
    }

    /** Rows still owing IdP propagation ({@code pending} or a previous {@code failed}) —
     *  the claim worker's sweep set, oldest mutate first. UNSCOPED. */
    public Flux<DesktopSudoGrant> pendingPropagation() {
        return repo.findByPropagationStateInOrderByGenerationAsc(
                        List.of(DesktopSudoGrant.PROP_PENDING, DesktopSudoGrant.PROP_FAILED))
                .map(DesktopSudoGrantRow::toDomain);
    }
}
