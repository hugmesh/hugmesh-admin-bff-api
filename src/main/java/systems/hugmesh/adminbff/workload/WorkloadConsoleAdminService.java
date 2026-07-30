package systems.hugmesh.adminbff.workload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Duration;
import java.time.Instant;

/**
 * The SUPERADMIN write surface for WORKLOAD CONSOLE grants + master config, plus the
 * scheduled expiry sweep. Clones the {@code SshLicenseService} idioms:
 * findActive-before-insert idempotency, monotonic generation bump on every mutate, CAS
 * revoke that never deletes. A grant is a LEASE: {@link #grant} stamps a ~24h TTL (DECISION
 * 4/6), {@code log_access} defaults FALSE, and {@link #sweepExpired} CASes active->expired
 * for past-TTL rows (returning the admin to dark automatically).
 *
 * <p>The grant's {@code domain}/{@code target_domain} are stamped from the GRANTEE's
 * resolved domain (the DB CHECK ties them equal), never a request body field, so a grant
 * can never span domains. A revoke/expiry bumps the grant generation; every stream re-reads
 * it per heartbeat to tear down (multi-replica invalidation — the predicate reads PRIMARY,
 * read-your-writes).
 */
@Service
public class WorkloadConsoleAdminService {

    private static final Logger log = LoggerFactory.getLogger(WorkloadConsoleAdminService.class);

    private final WorkloadConsoleGrantRepository grants;
    private final WorkloadConsoleConfigRepository configs;
    private final DomainRegistry domainRegistry;
    private final WorkloadConsoleProperties props;

    public WorkloadConsoleAdminService(WorkloadConsoleGrantRepository grants,
                                       WorkloadConsoleConfigRepository configs,
                                       DomainRegistry domainRegistry,
                                       WorkloadConsoleProperties props) {
        this.grants = grants;
        this.configs = configs;
        this.domainRegistry = domainRegistry;
        this.props = props;
    }

    // ── grants ───────────────────────────────────────────────────────────────────

    /**
     * Issue a READ_ONLY grant LEASE for {@code grantee} in {@code targetDomain}.
     * Idempotent: an existing active grant for (grantee, targetDomain) is returned (its
     * log_access/TTL are NOT silently widened — a re-grant to change them is an explicit
     * revoke + re-grant). The TTL defaults to {@code grantTtlHours} (~24h) unless a shorter
     * explicit TTL is given. {@code targetDomain} must be a known brand and never 'default'
     * (the per-domain SSH/console boundary would be vacuous otherwise).
     */
    public Mono<WorkloadConsoleGrant> grant(String grantee, String targetDomain, boolean logAccess,
                                            Long ttlHours, String grantedBy) {
        // Validate inputs, derive TTL, then idempotently issue (return existing active grant if any).
        return Mono.defer(() -> issueGrantIfValid(grantee, targetDomain, logAccess, ttlHours, grantedBy));
    }

    /** Validate grantee/domain inputs, compute TTL, then return existing or insert a new grant. */
    private Mono<WorkloadConsoleGrant> issueGrantIfValid(String grantee, String targetDomain,
                                                          boolean logAccess, Long ttlHours,
                                                          String grantedBy) {
        if (grantee == null || grantee.isBlank()) {
            return Mono.error(new IllegalArgumentException("grantee is required"));
        }
        if (targetDomain == null || targetDomain.isBlank()) {
            return Mono.error(new IllegalArgumentException("target domain is required"));
        }
        if (DomainRegistry.DEFAULT_DOMAIN.equals(targetDomain)) {
            return Mono.error(new IllegalArgumentException(
                    "target domain must not be 'default' — a per-domain console boundary "
                    + "cannot be drawn on a single-issuer cluster"));
        }
        long hours = ttlHours != null && ttlHours > 0 ? ttlHours : props.getGrantTtlHours();
        Instant expiresAt = Instant.now().plus(Duration.ofHours(hours));
        // Return existing active grant (no silent widening) or insert a new one.
        return grants.findActive(grantee, targetDomain)
                .switchIfEmpty(Mono.defer(() -> insertNewGrant(grantee, targetDomain, logAccess,
                        expiresAt, grantedBy, hours)));
    }

    /** Allocate a generation slot and insert a new READ_ONLY grant for (grantee, targetDomain). */
    private Mono<WorkloadConsoleGrant> insertNewGrant(String grantee, String targetDomain,
                                                       boolean logAccess, Instant expiresAt,
                                                       String grantedBy, long hours) {
        return grants.maxGeneration().flatMap(maxGen -> {
            WorkloadConsoleGrant draft = new WorkloadConsoleGrant(null, grantee,
                    targetDomain, WorkloadConsoleGrant.ACCESS_READ_ONLY, logAccess,
                    WorkloadConsoleGrant.STATE_ACTIVE, grantedBy, null, expiresAt,
                    null, null, targetDomain, WorkloadConsoleGrant.PROP_PENDING, maxGen + 1);
            return grants.insertActive(draft, maxGen + 1)
                    .doOnNext(g -> log.info("[workload-console] grant issued by {} for grantee in "
                            + "domain {} (log_access={}, ttl={}h)", grantedBy, targetDomain,
                            logAccess, hours));
        });
    }

    /** Revoke a grant by id (CAS active->revoked, generation bump). Returns rows-updated. */
    public Mono<Long> revoke(String id, String revokedBy) {
        return grants.maxGeneration()
                .flatMap(maxGen -> grants.revoke(id, revokedBy, maxGen + 1))
                .doOnNext(n -> {
                    if (n > 0) log.info("[workload-console] grant {} revoked by {}", id, revokedBy);
                });
    }

    public Flux<WorkloadConsoleGrant> listGrants(PrincipalDomain scope) {
        return grants.list(scope);
    }

    // ── config (master kill-switch) ───────────────────────────────────────────────

    public Flux<WorkloadConsoleConfig> listConfig() {
        return configs.listAll();
    }

    public Mono<WorkloadConsoleConfig> getConfig(String domain) {
        return configs.find(domain);
    }

    /**
     * Upsert the master config for a domain (or the GLOBAL sentinel). A superadmin flips
     * admin_enabled / dangerous_tier_enabled here. The generation bumps so every open stream
     * re-reads it per heartbeat and tears down on a kill (multi-replica invalidation).
     */
    public Mono<WorkloadConsoleConfig> putConfig(String domain, boolean adminEnabled,
                                                 boolean dangerousTierEnabled, String updatedBy) {
        return configs.maxGeneration()
                .flatMap(maxGen -> configs.upsert(domain, adminEnabled, dangerousTierEnabled,
                        updatedBy, maxGen + 1))
                .doOnNext(c -> log.warn(
                        "[workload-console] CONFIG flip by {} domain={} admin_enabled={} "
                        + "dangerous_tier_enabled={}", updatedBy, domain, adminEnabled,
                        dangerousTierEnabled));
    }

    // ── expiry sweep (scheduled — see WorkloadConsoleExpirySweep) ─────────────────

    /** CAS active->expired for every grant past its TTL. Returns the count expired. */
    public Mono<Long> sweepExpired() {
        Instant now = Instant.now();
        return grants.dueForExpiry(now)
                .concatMap(g -> grants.maxGeneration()
                        .flatMap(maxGen -> grants.markExpired(g.id(), maxGen + 1)))
                .reduce(0L, Long::sum)
                .doOnNext(n -> {
                    if (n > 0) log.info("[workload-console] expiry sweep expired {} grant(s)", n);
                });
    }
}
