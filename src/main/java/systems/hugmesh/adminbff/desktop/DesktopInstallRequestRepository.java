package systems.hugmesh.adminbff.desktop;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code desktop_install_request} — the user-submitted
 * allow/install requests (schema in Liquibase {@code db/changelog/140-desktop-app-governance.xml}).
 *
 * <p>Backed by the Spring Data {@link DesktopInstallRequestR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DesktopInstallRequestRow} entity to/from the
 * {@link DesktopInstallRequest} domain record.
 *
 * <h3>owner == subject (the user read is double-scoped)</h3>
 * {@link #listForRequester} filters on BOTH {@code domain} AND {@code requester}, and
 * {@link #findByIdForRequester} likewise — so a user can ONLY ever see their OWN requests
 * (negative cross-user isolation). The ADMIN read ({@link #list}) is brand-scoped via the
 * usual {@code scope.scoped() ? WHERE domain : unscoped} branch. The decide is a SCOPED CAS
 * {@code pending -> approved/denied/installed} (never deleted = audit).
 */
@Repository
public class DesktopInstallRequestRepository {

    private final DesktopInstallRequestR2dbcRepository repo;

    public DesktopInstallRequestRepository(DesktopInstallRequestR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── submit (user; owner == subject) ─────────────────────────────────────────

    /** Insert a new PENDING request (app-generated id). {@code requester} is the JWT subject
     *  and {@code domain} the validated issuer — both caller-derived, never body fields. */
    public Mono<DesktopInstallRequest> insertPending(String requester, String appRef,
                                                     String deviceId, String domain) {
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set decided_by/decided_at (default NULL); RETURNING id hands back
        // the generated string, mapped into the persisted request with the SAME field
        // order/values as before.
        return repo.insertReturningId(requester, appRef, deviceId,
                        DesktopInstallRequest.STATUS_PENDING, domain, createdAt)
                .map(genId -> new DesktopInstallRequest(genId, requester, appRef, deviceId,
                        DesktopInstallRequest.STATUS_PENDING, null, null, domain, createdAt));
    }

    // ── user read (owner == subject; double-scoped) ─────────────────────────────

    /** The requester's OWN requests in their OWN brand (negative cross-user isolation). */
    public Flux<DesktopInstallRequest> listForRequester(String requester, String domain) {
        return repo.findByRequesterAndDomainOrderByCreatedAtDesc(requester, domain)
                .map(DesktopInstallRequestRow::toDomain);
    }

    /** One of the requester's own requests by id (double-scoped — invisible to others). */
    public Mono<DesktopInstallRequest> findByIdForRequester(String id, String requester, String domain) {
        return repo.findByIdAndRequesterAndDomain(id, requester, domain)
                .map(DesktopInstallRequestRow::toDomain);
    }

    // ── admin read (brand-scoped) ───────────────────────────────────────────────

    /** ALL requests VISIBLE to the given tenant scope — the ADMIN inbox (own brand;
     *  SUPERADMIN all). */
    public Flux<DesktopInstallRequest> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByCreatedAtDesc(domain)
                    .map(DesktopInstallRequestRow::toDomain);
        }
        return repo.findByOrderByDomainAscCreatedAtDesc().map(DesktopInstallRequestRow::toDomain);
    }

    /** One request by id, SCOPED (a scoped admin cannot resolve another brand's request). */
    public Mono<DesktopInstallRequest> findById(String id, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByIdAndDomain(id, domain).map(DesktopInstallRequestRow::toDomain);
        }
        return repo.findById(id).map(DesktopInstallRequestRow::toDomain);
    }

    // ── decide (admin; scoped CAS pending -> terminal) ──────────────────────────

    /**
     * Compare-and-swap {@code pending -> newStatus} for one request, SCOPED so a scoped
     * admin can only decide their own brand's requests AND only from {@code pending}
     * (single-winner; a second decide is a no-op). Stamps {@code decided_by}/{@code
     * decided_at}. Returns rows-updated (1 = decided, 0 = already decided / absent / out of
     * scope).
     */
    public Mono<Long> decide(String id, String newStatus, String decidedBy, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.decideScoped(id, newStatus, decidedBy, domain);
        }
        return repo.decideAll(id, newStatus, decidedBy);
    }
}
