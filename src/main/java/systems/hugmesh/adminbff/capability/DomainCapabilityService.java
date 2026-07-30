package systems.hugmesh.adminbff.capability;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

/**
 * The DOMAIN CAPABILITY GATE service — the truth {@link #isActive} answers for a SERVICE
 * caller (e.g. user-bff's mesh-device claim path, over {@code
 * GET /bff/internal/domain-capabilities/{domain}/{capability}}), plus the two write keys a
 * SUPERADMIN ({@link #grant}) and a domain ADMIN ({@link #enable}) each own independently.
 *
 * <p>Two-tier, fail-closed: {@link #isActive} is TRUE only when the GLOBAL
 * {@link DomainCapability#GLOBAL_DOMAIN} row's {@code granted} (the platform-wide kill) is
 * true AND the per-domain row is {@link DomainCapability#active()} (its OWN
 * {@code granted} AND {@code enabled}). An absent row of either kind, or any repository
 * error, resolves to {@code false} — never throws, never fails open.
 *
 * <p>{@link #grant} and {@link #enable} each touch ONLY their own key: a read-modify-write
 * that preserves whichever key the OTHER endpoint owns (a SUPERADMIN grant must not clobber
 * an admin's prior {@code enabled} choice, and vice versa) — mirrors
 * {@code WorkloadConsoleAdminService#putConfig}'s monotonic generation-bump upsert, split
 * across two independent callers instead of one combined body.
 */
@Service
public class DomainCapabilityService {

    private static final Logger log = LoggerFactory.getLogger(DomainCapabilityService.class);

    private final DomainCapabilityRepository repo;

    public DomainCapabilityService(DomainCapabilityRepository repo) {
        this.repo = repo;
    }

    // ── the two-tier active predicate (SERVICE callers) ─────────────────────────────

    /**
     * TRUE iff the GLOBAL platform-wide kill is on AND {@code domain} has been BOTH
     * granted (SUPERADMIN) and enabled (domain ADMIN) for {@code capability}. Absent rows
     * and repository errors both resolve to {@code false} (fail-closed) — this is the
     * ONLY check a claim-path caller needs.
     */
    public Mono<Boolean> isActive(String domain, String capability) {
        Mono<Boolean> globalGranted = repo.find(DomainCapability.GLOBAL_DOMAIN, capability)
                .map(DomainCapability::granted).defaultIfEmpty(false);
        Mono<Boolean> perDomainActive = repo.find(domain, capability)
                .map(DomainCapability::active).defaultIfEmpty(false);
        return Mono.zip(globalGranted, perDomainActive)
                .map(t -> t.getT1() && t.getT2())
                .onErrorResume(e -> {
                    log.warn("[domain-capability] isActive lookup error for domain={} "
                            + "capability={}: {} — failing closed", domain, capability, e.toString());
                    return Mono.just(false);
                });
    }

    // ── reads (admin surface) ───────────────────────────────────────────────────────

    /** Gate rows visible to {@code scope}: a SUPERADMIN sees every domain; a scoped ADMIN
     *  sees ONLY their own domain's rows (never the GLOBAL sentinel, never another
     *  brand's). Mirrors {@code NodeRadioService}/{@code RadioDeviceRepository#list}. */
    public Flux<DomainCapability> listForScope(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.listForDomain(domain);
        }
        return repo.listAll();
    }

    // ── writes (each touches ONLY its own key) ──────────────────────────────────────

    /**
     * The SUPERADMIN key: grant (or revoke) {@code capability} for {@code domain}. On the
     * GLOBAL sentinel domain this IS the platform-wide kill. Preserves the row's current
     * {@code enabled} value (the domain ADMIN's independent key) — a grant/revoke never
     * silently flips the admin's own opt-in.
     */
    public Mono<DomainCapability> grant(String domain, String capability, boolean granted,
                                        String updatedBy) {
        return repo.find(domain, capability)
                .map(DomainCapability::enabled)
                .defaultIfEmpty(false)
                .flatMap(currentEnabled -> upsert(domain, capability, granted, currentEnabled, updatedBy))
                .doOnNext(c -> log.warn("[domain-capability] GRANT flip by {} domain={} "
                        + "capability={} granted={}", updatedBy, domain, capability, granted));
    }

    /**
     * The domain ADMIN key: opt {@code domain} in (or out) of {@code capability}.
     * Preserves the row's current {@code granted} value (the SUPERADMIN's independent
     * key) — an enable/disable never silently grants or revokes.
     */
    public Mono<DomainCapability> enable(String domain, String capability, boolean enabled,
                                         String updatedBy) {
        return repo.find(domain, capability)
                .map(DomainCapability::granted)
                .defaultIfEmpty(false)
                .flatMap(currentGranted -> upsert(domain, capability, currentGranted, enabled, updatedBy))
                .doOnNext(c -> log.info("[domain-capability] ENABLE flip by {} domain={} "
                        + "capability={} enabled={}", updatedBy, domain, capability, enabled));
    }

    private Mono<DomainCapability> upsert(String domain, String capability, boolean granted,
                                          boolean enabled, String updatedBy) {
        return repo.maxGeneration()
                .flatMap(maxGen -> repo.upsert(domain, capability, granted, enabled, updatedBy,
                        maxGen + 1));
    }
}
