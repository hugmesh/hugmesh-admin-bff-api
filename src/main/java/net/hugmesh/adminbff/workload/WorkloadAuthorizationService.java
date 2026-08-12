package net.hugmesh.adminbff.workload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.Roles;
import net.hugmesh.adminbff.suspension.SuspensionService;

import java.time.Instant;

/**
 * The TOTAL WORKLOAD CONSOLE authorization predicate — the single decision point the central
 * {@link WorkloadAuthorizationFilter} (and the per-heartbeat stream re-authz) call. No
 * controller is reachable without this; the predicate keys on the {@link DangerTier}, NEVER
 * on the HTTP verb.
 *
 * <h3>STEP 0..7 (the spec's exact order)</h3>
 * <ol start="0">
 *   <li><b>STEP 0</b> — GLOBAL dangerous-tier kill, evaluated BEFORE the superadmin
 *       short-circuit: if the requested tier is {@link DangerTier#DANGEROUS} and the GLOBAL
 *       config row's {@code dangerous_tier_enabled} is false, DENY (403) — applies EVEN to a
 *       superadmin (DECISION 5).</li>
 *   <li><b>STEP 0b</b> — namespace allowlist, checked BEFORE any k8s call: a {@code ns} not
 *       in the app-tier allowlist is a 403 + probe audit (the caller records it). (Done by the
 *       filter from the path; this service trusts the {@code namespaceOk} flag it is handed.)</li>
 *   <li><b>STEP 1</b> — SUPERADMIN → suspension-check + step-up-for-DANGEROUS → ALLOW.</li>
 *   <li><b>STEP 2</b> — non-admin → DENY (404, no existence leak).</li>
 *   <li><b>STEP 3</b> — a non-SA can NEVER reach {@link DangerTier#RUNTIME_MUTATE}/
 *       {@link DangerTier#DANGEROUS} (tier-based, not verb-based) → DENY (404).</li>
 *   <li><b>STEP 4</b> — GLOBAL admin kill ({@code admin_enabled}=false) → DENY (404).</li>
 *   <li><b>STEP 5</b> — per-domain master (a per-domain row present AND admin_enabled=false)
 *       → DENY (404).</li>
 *   <li><b>STEP 6</b> — an active, unexpired grant matched ONLY on (subject, issuer-derived
 *       domain) + READ_ONLY (+ {@code log_access} for log paths) → else DENY (404).</li>
 *   <li><b>STEP 7</b> — owner-chain attribution (the controller asserts the inspected
 *       workload's owner-chain domain == the scope domain, else DENY+audit) — enforced
 *       downstream in the read controller, not here (this service has no k8s handle).</li>
 * </ol>
 */
@Service
public class WorkloadAuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(WorkloadAuthorizationService.class);

    private final WorkloadConsoleGrantRepository grants;
    private final WorkloadConsoleConfigRepository configs;
    private final SuspensionService suspensions;
    private final DomainRegistry domainRegistry;
    private final WorkloadStepUpService stepUp;

    public WorkloadAuthorizationService(WorkloadConsoleGrantRepository grants,
                                        WorkloadConsoleConfigRepository configs,
                                        SuspensionService suspensions,
                                        DomainRegistry domainRegistry,
                                        WorkloadStepUpService stepUp) {
        this.grants = grants;
        this.configs = configs;
        this.suspensions = suspensions;
        this.domainRegistry = domainRegistry;
        this.stepUp = stepUp;
    }

    /**
     * The full STEP 0..7 decision. {@code logPath} marks a request for a log BODY (gated on
     * the grant's {@code log_access}); {@code stepUpToken} is the presented DANGEROUS-tier
     * step-up token (validated for SA DANGEROUS requests); {@code namespaceOk} is the STEP-0b
     * result the filter computed from the path.
     */
    public Mono<WorkloadAccessDecision> decide(Authentication auth, DangerTier tier,
                                               boolean logPath, boolean namespaceOk,
                                               String stepUpToken) {
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt)) {
            return Mono.just(WorkloadAccessDecision.notFound("no authentication"));
        }
        boolean superadmin = Roles.isSuperadmin(jwt);
        boolean admin = Roles.isAdmin(jwt);
        String subject = jwt.getSubject();
        String suspensionHandle = suspensionHandleOf(jwt);
        String domain = Roles.domainOf(jwt, domainRegistry);

        // STEP 0b — namespace allowlist already checked by the filter; out-of-allowlist is a
        // 403 + probe audit (the filter records the audit). Defence: re-deny here too.
        if (!namespaceOk) {
            return Mono.just(WorkloadAccessDecision.forbidden("namespace not in app-tier allowlist"));
        }

        return configs.find(WorkloadConsoleConfig.GLOBAL_DOMAIN)
                .map(c -> (Boolean) c.dangerousTierEnabled()).defaultIfEmpty(Boolean.FALSE)
                // STEP 0→6: global dangerous-kill, superadmin/admin tier, admin read gate.
                .flatMap(globalDangerEnabled -> applyAccessDecision(globalDangerEnabled,
                        superadmin, admin, subject, suspensionHandle, domain, tier, logPath,
                        stepUpToken));
    }

    /**
     * The handle {@link SuspensionService#statusFor} must be keyed on for this JWT's identity.
     * Suspension rows are stored under {@code matrixUser(localpartSeed(handle))} where the handle
     * is the account's email / provider username ({@link SuspensionService#suspend}), and every
     * shipped suspension gate reads them under that same person-handle (the bff_ session gate,
     * the custody-exchange gate, {@code /bff/me}, {@code /bff/login} — all pass
     * {@code account.handle()}). The JWT reaching this service is the custody-exchanged Casdoor
     * access JWT, whose {@code sub} is Casdoor's opaque generated user id — it matches NO stored
     * localpart, so keying statusFor on it fails OPEN for a suspended superadmin. Derive the
     * handle from the identity claims with the same {@code email > preferred_username > sub}
     * precedence native login uses to derive {@code account.handle()}
     * (InternalAccountController#SUBJECT_CLAIMS / AuthController#accountFromJwt); the {@code sub}
     * fallback keeps a claims-less JWT behaving exactly as before. ONLY the suspension lookup
     * keys on this — grants and step-up remain keyed on {@code jwt.getSubject()} (grants are
     * minted under the sub, see WorkloadSuperadminController#subject).
     */
    private static String suspensionHandleOf(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        if (email != null && !email.isBlank()) return email;
        String username = jwt.getClaimAsString("preferred_username");
        if (username != null && !username.isBlank()) return username;
        return jwt.getSubject();
    }

    /** STEP 4/5/6 for an admin READ request. */
    private Mono<WorkloadAccessDecision> adminReadAllowed(String subject, String domain,
                                                          boolean logPath) {
        Mono<Boolean> globalAdminEnabled = configs.find(WorkloadConsoleConfig.GLOBAL_DOMAIN)
                .map(WorkloadConsoleConfig::adminEnabled).defaultIfEmpty(Boolean.FALSE);
        Mono<java.util.Optional<WorkloadConsoleConfig>> perDomain = configs.find(domain)
                .map(java.util.Optional::of).defaultIfEmpty(java.util.Optional.empty());
        Mono<java.util.Optional<WorkloadConsoleGrant>> grant = grants.findActive(subject, domain)
                .map(java.util.Optional::of).defaultIfEmpty(java.util.Optional.empty());

        return Mono.zip(globalAdminEnabled, perDomain, grant)
                // Evaluate global/per-domain kill switches and grant validity (STEPS 4–6).
                .map(t -> evaluateAdminReadAccess(t.getT1(), t.getT2(), t.getT3(), logPath));
    }

    /** STEP 0→6: global dangerous-kill, superadmin path, admin path (READ only). */
    private Mono<WorkloadAccessDecision> applyAccessDecision(boolean globalDangerEnabled,
                                                              boolean superadmin, boolean admin,
                                                              String subject, String suspensionHandle,
                                                              String domain,
                                                              DangerTier tier, boolean logPath,
                                                              String stepUpToken) {
        // STEP 0 — GLOBAL dangerous-tier kill BEFORE the superadmin short-circuit.
        if (tier == DangerTier.DANGEROUS && !globalDangerEnabled) {
            return Mono.just(WorkloadAccessDecision.forbidden(
                    "dangerous tier is globally disabled (dangerous_tier_enabled=false)"));
        }
        // STEP 1 — SUPERADMIN. The suspension read keys on the identity-claim handle (the key
        // form suspension rows are stored under — see suspensionHandleOf); grants + step-up
        // below stay keyed on the JWT sub.
        if (superadmin) {
            return suspensions.statusFor(suspensionHandle)
                    .map(status -> decideSuperadminAccess(status, tier, subject, stepUpToken))
                    .onErrorResume(e -> superadminFallback(e, tier, subject, stepUpToken));
        }
        // STEP 2 — a non-admin can never use the console.
        if (!admin) {
            return Mono.just(WorkloadAccessDecision.notFound("not an admin"));
        }
        // STEP 3 — a non-SA can NEVER reach RUNTIME_MUTATE/DANGEROUS.
        if (tier != DangerTier.READ) {
            return Mono.just(WorkloadAccessDecision.notFound("admins are read-only; tier requires superadmin"));
        }
        // STEP 4/5/6 — admin READ: GLOBAL admin kill, per-domain master, active grant.
        return adminReadAllowed(subject, domain, logPath);
    }

    /** Evaluate a superadmin suspension status and step-up requirement for DANGEROUS tier. */
    private WorkloadAccessDecision decideSuperadminAccess(
            net.hugmesh.authcore.account.AccountStatus status,
            DangerTier tier, String subject, String stepUpToken) {
        // A suspended/banned superadmin session is denied.
        if (status != null && !status.isActive()) {
            return WorkloadAccessDecision.forbidden("superadmin session is suspended");
        }
        // Step-up required for DANGEROUS tier.
        if (tier == DangerTier.DANGEROUS && !stepUp.validate(subject, stepUpToken)) {
            return WorkloadAccessDecision.forbidden("dangerous tier requires a valid step-up token");
        }
        return WorkloadAccessDecision.allow(true, true);
    }

    /** Fail-closed superadmin fallback: still enforce step-up for DANGEROUS, allow otherwise. */
    private Mono<WorkloadAccessDecision> superadminFallback(Throwable e, DangerTier tier,
                                                             String subject, String stepUpToken) {
        // fail-closed on any suspension lookup error: still require step-up for DANGEROUS.
        log.warn("[workload-authz] superadmin suspension check error: {}", e.toString());
        if (tier == DangerTier.DANGEROUS && !stepUp.validate(subject, stepUpToken)) {
            return Mono.just(WorkloadAccessDecision.forbidden(
                    "dangerous tier requires a valid step-up token"));
        }
        return Mono.just(WorkloadAccessDecision.allow(true, true));
    }

    /** STEPS 4–6: evaluate global/per-domain kill switches and grant validity for admin READ. */
    private static WorkloadAccessDecision evaluateAdminReadAccess(
            Boolean globalOn,
            java.util.Optional<WorkloadConsoleConfig> pd,
            java.util.Optional<WorkloadConsoleGrant> g,
            boolean logPath) {
        // STEP 4 — GLOBAL admin kill.
        if (!Boolean.TRUE.equals(globalOn)) {
            return WorkloadAccessDecision.notFound("admin console globally disabled");
        }
        // STEP 5 — per-domain master (present AND off => deny; absent => inherit on).
        if (pd.isPresent() && !pd.get().adminEnabled()) {
            return WorkloadAccessDecision.notFound("admin console disabled for domain");
        }
        // STEP 6 — active unexpired READ_ONLY grant matched on (subject, domain).
        if (g.isEmpty() || !g.get().isLiveAt(Instant.now())) {
            return WorkloadAccessDecision.notFound("no active grant");
        }
        WorkloadConsoleGrant grantRow = g.get();
        if (!WorkloadConsoleGrant.ACCESS_READ_ONLY.equals(grantRow.accessLevel())) {
            return WorkloadAccessDecision.notFound("grant is not read-only");
        }
        // Log BODIES require the separate log_access opt-in (DECISION 4).
        if (logPath && !grantRow.logAccess()) {
            return WorkloadAccessDecision.notFound("grant does not include log access");
        }
        return WorkloadAccessDecision.allow(false, grantRow.logAccess());
    }
}
