package net.hugmesh.adminbff;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.federation.FederationApiClient;
import net.hugmesh.adminbff.federation.ModerationDecisionDto;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.urlregistry.UrlRoute;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.dto.AllowlistRequest;
import net.hugmesh.adminbff.web.dto.DomainLockRequest;
import net.hugmesh.adminbff.web.dto.NamespaceAccessRequest;
import net.hugmesh.adminbff.web.dto.RouteRuleDeleteRequest;
import net.hugmesh.adminbff.web.dto.RouteRuleRequest;
import net.hugmesh.adminbff.web.dto.SuspensionRequest;
import net.hugmesh.adminbff.web.dto.UrlRouteRequest;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;
import net.hugmesh.authcore.reserved.ReservedNames;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.authcore.username.UsernameGateException;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.security.RoleName;
import net.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Admin endpoints (reactive). Admin gating is DEFENCE IN DEPTH: the be/fe-gateway
 * denies {@code /bff/admin/**} to non-admins via the Postgres route-access rules,
 * the resource-server filter chain re-applies {@code hasRole('ADMIN')} on the
 * path, AND {@code @PreAuthorize("hasRole('ADMIN')")} re-checks at the method.
 *
 * <p>Allowlist + namespace grants are now DURABLE (R2DBC {@link AccountStore});
 * route-access is persisted in Postgres with a best-effort Cassandra mirror.
 * Usage is aggregated from ClickHouse with an in-memory fallback. When an admin
 * invites/clears an account the durable allowlist row is written AND — if the
 * real Casdoor admin write client is enabled ({@code casdoor.admin.enabled}) —
 * the Casdoor user/role is created/enabled (or disabled), best-effort so a
 * Casdoor failure never loses the allowlist row.
 */
@RestController
@RequestMapping("/bff/admin")
@Validated
public class AdminController {

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);

    private final AccountStore store;
    private final RouteAccessService routeAccess;
    private final UrlRegistryService urlRegistry;
    private final IsoRepository isoRepo;
    private final UsageService usage;
    private final SuspensionService suspensions;
    /** Domain-lock (force local-only) desired-state surface — the ADD-active sibling
     *  of {@link SuspensionService}. */
    private final DomainLockService domainLocks;
    /** The real Casdoor admin write client; null unless casdoor.admin.enabled=true. */
    @Nullable private final CasdoorAdminClient casdoor;
    /** Gateway revocation client — writes {@code subject:<casdoorSub>} keys on role
     *  revoke so stale custody JWTs are denied at the gateway within the revocation
     *  poll cycle rather than waiting for natural TTL expiry (~1 h). Best-effort;
     *  gated on {@code broker.gateway-revocation.enabled} (default false). */
    private final GatewayRevocationClient revocations;
    /** Username-derivation gate (reserved + federation confusable check). */
    private final UsernameGate usernameGate;
    /** Issuer-&gt;domain registry — used to resolve the acting principal's tenant scope
     *  (their brand) from the cryptographically-validated JWT issuer. */
    private final DomainRegistry domainRegistry;
    /** Proxy to hugmesh-federation-api for appeals adjudication (the admin-ui
     *  appeals console's decide action). The caller's JWT is bearer-forwarded so
     *  federation-api applies its OWN ADMIN gate + per-domain scope downstream. */
    private final FederationApiClient federation;

    public AdminController(AccountStore store, RouteAccessService routeAccess,
                           UrlRegistryService urlRegistry, IsoRepository isoRepo, UsageService usage,
                           SuspensionService suspensions,
                           DomainLockService domainLocks,
                           UsernameGate usernameGate,
                           DomainRegistry domainRegistry,
                           FederationApiClient federation,
                           GatewayRevocationClient revocations,
                           @Nullable CasdoorAdminClient casdoor) {
        this.store = store;
        this.routeAccess = routeAccess;
        this.urlRegistry = urlRegistry;
        this.isoRepo = isoRepo;
        this.usage = usage;
        this.suspensions = suspensions;
        this.domainLocks = domainLocks;
        this.usernameGate = usernameGate;
        this.domainRegistry = domainRegistry;
        this.federation = federation;
        this.revocations = revocations;
        this.casdoor = casdoor;
    }

    /**
     * The tenant SCOPE the acting principal operates under, resolved from their
     * validated Casdoor JWT issuer. A brand-scoped ADMIN is constrained to their own
     * brand's rows; SUPERADMIN is unscoped (sees + mutates all brands). See
     * {@link PrincipalDomain}.
     */
    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    // ── Admin-managed Gmail/Discord allowlist ──────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Allowlist", operationId = "adminAllowlist")
    @GetMapping("/allowlist")
    public Mono<Map<String, Object>> allowlist(Authentication auth) {
        return allowlistOut(scope(auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Invite", operationId = "adminInvite")
    @PostMapping("/allowlist")
    public Mono<ResponseEntity<Map<String, Object>>> invite(@Valid @RequestBody AllowlistRequest b, Authentication auth) {
        String email = str(b.email());
        String discord = str(b.discord());
        // API-LAYER GATE (defence-in-depth): the username the Casdoor mint would
        // derive from each handle is checked against the reserved list + the
        // federation confusable engine BEFORE anything is written. A RESERVED
        // (or non-disambiguable confusable) derived username is a hard 422 here —
        // the invite is refused outright rather than silently renamed — so the
        // admin gets immediate feedback. The SERVICE layer (CasdoorAdminClient)
        // re-applies the gate and auto-disambiguates any remaining confusable/
        // exact collision when it mints.
        // Gate: run username checks then perform the durable allowlist + Casdoor writes.
        return guardDerivedUsernames(email, discord)
                .flatMap(rejection -> processInviteRejection(rejection, email, discord, auth));
    }

    /** Write allowlist rows + Casdoor records for a validated invite.
     *  An empty rejection map means "proceed"; a populated one is a hard 422. */
    private Mono<ResponseEntity<Map<String, Object>>> processInviteRejection(
            Map<String, Object> rejection, String email, String discord, Authentication auth) {
        if (!rejection.isEmpty()) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNPROCESSABLE_CONTENT).body(rejection));
        }
        PrincipalDomain scope = scope(auth);
        String domain = scope.domain();
        // 1) Durable allowlist row(s) — the registration gate; stamped with acting admin's
        //    domain so brand-X admins only ever see/manage their own brand's allowlist.
        // 2) Real Casdoor user/role write (best-effort). BOTH happen; Casdoor never loses the row.
        Mono<Void> writes = Mono.empty();
        if (email != null) {
            writes = writes
                    .then(store.inviteEmail(email, domain))
                    .then(casdoorEnsure("google", email, email,
                            store.admins().contains(email.toLowerCase())
                                    ? List.of(RoleName.USER.value(), RoleName.ADMIN.value())
                                    : List.of(RoleName.USER.value())));
        }
        if (discord != null) {
            writes = writes
                    .then(store.inviteDiscord(discord, domain))
                    .then(casdoorEnsure("discord", discord, null, List.of(RoleName.USER.value())));
        }
        // Record usage then return the updated allowlist (scoped to caller's domain).
        return writes
                .then(Mono.fromRunnable(() -> usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.invite").subscribe()))
                .then(allowlistOut(scope))
                .map(ResponseEntity::ok);
    }

    /**
     * Pre-flight gate for the invite: derive the Casdoor username each handle
     * would mint and check it against the reserved list + the federation
     * confusable engine. Emits a populated error body (→ 422) when a derived
     * username is a HARD reject (reserved, or a confusable that cannot be
     * auto-disambiguated), else emits an EMPTY map (proceed). Confusable/exact
     * collisions that the service layer can disambiguate do NOT block here.
     */
    private Mono<Map<String, Object>> guardDerivedUsernames(String email, String discord) {
        Mono<Map<String, Object>> chain = Mono.just(Map.of());   // empty = "ok / proceed"
        if (email != null) {
            chain = chain.flatMap(prev -> prev.isEmpty()
                    ? gateRejection("google", email)
                    : Mono.just(prev));
        }
        if (discord != null) {
            chain = chain.flatMap(prev -> prev.isEmpty()
                    ? gateRejection("discord", discord)
                    : Mono.just(prev));
        }
        return chain;
    }

    /**
     * Run the gate on the username derived from a single handle. Emits an empty
     * map (the "ok / proceed" sentinel) when the candidate is mintable as-is OR
     * is a confusable/exact collision the service layer will disambiguate; emits
     * a populated error body ONLY for a HARD reject (reserved / non-recoverable).
     */
    private Mono<Map<String, Object>> gateRejection(String provider, String handle) {
        String candidate = CasdoorAdminClient.usernameOf(provider, handle);
        return usernameGate.resolve(candidate)
                .map(resolved -> Map.<String, Object>of())   // mintable (possibly disambiguated) → proceed
                // Map hard gate rejections to a 422 error body.
                .onErrorResume(UsernameGateException.class,
                        ex -> buildUsernameGateError(provider, candidate, ex));
    }

    /** Build a 422 error body for a hard username-gate rejection (reserved or non-recoverable). */
    private static Mono<Map<String, Object>> buildUsernameGateError(
            String provider, String candidate, UsernameGateException ex) {
        Map<String, Object> err = new LinkedHashMap<>();
        if ("reserved".equals(ex.reason())) {
            err.put("error", "derived username '" + candidate + "' is reserved and cannot be provisioned");
        } else {
            // Federation outage / exhausted disambiguation → fail-closed 422.
            err.put("error", "derived username '" + candidate
                    + "' could not be provisioned: " + ex.getMessage());
        }
        err.put("provider", provider);
        err.put("candidate", candidate);
        err.put("reason", ex.reason());
        return Mono.just(err);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Uninvite", operationId = "adminUninvite")
    @DeleteMapping("/allowlist")
    public Mono<Map<String, Object>> uninvite(@Valid @RequestBody AllowlistRequest b, Authentication auth) {
        String email = str(b.email());
        String discord = str(b.discord());
        PrincipalDomain scope = scope(auth);
        String domain = scope.domain();
        // Domain-scoped revoke: a brand-X admin can only remove handles from their own
        // brand's allowlist. The SQL WHERE domain=:domain clause silently no-ops for
        // handles that belong to a different brand — verify-never-wrote behaviour.
        Mono<Void> writes = Mono.empty();
        if (email != null) {
            writes = writes.then(store.revokeEmail(email, domain))
                    .then(casdoorDisable("google", email))
                    .then(revokeOnDisable("google", email));
        }
        if (discord != null) {
            writes = writes.then(store.revokeDiscord(discord, domain))
                    .then(casdoorDisable("discord", discord))
                    .then(revokeOnDisable("discord", discord));
        }
        return writes.then(allowlistOut(scope));
    }

    /**
     * Invalidate any live custody JWT for an account being uninvited/disabled, so a bare
     * account-disable (with no accompanying ban/suspension) cannot be exercised for the
     * remaining natural token TTL (~1 h). Symmetric to the role-revoke path
     * ({@link #revokeRole}); the subject is the Casdoor username ({@code usernameOf}) — NOT
     * the raw email/handle — so the {@code subject:} key matches the JWT {@code sub} the
     * gateway revocation filter compares. Independent of {@code casdoor} (the allowlist row,
     * not Casdoor, is authoritative, and {@code GatewayRevocationClient} is internally
     * best-effort + gated on {@code broker.gateway-revocation.enabled} → a no-op in dev).
     */
    private Mono<Void> revokeOnDisable(String provider, String handle) {
        return revocations.revokeSubject(
                CasdoorAdminClient.usernameOf(provider, handle), "account-disable", 3_600L);
    }

    /** Best-effort Casdoor create/enable — logs + swallows so the allowlist row stands. */
    private Mono<Void> casdoorEnsure(String provider, String handle, String email, List<String> roles) {
        if (casdoor == null) return Mono.empty();
        return casdoor.ensureUser(provider, handle, email, roles)
                .onErrorResume(e -> {
                    log.warn("[casdoor] best-effort ensureUser {}:{} failed (allowlist row kept): {}",
                            provider, handle, e.toString());
                    return Mono.empty();
                });
    }

    private Mono<Void> casdoorDisable(String provider, String handle) {
        if (casdoor == null) return Mono.empty();
        return casdoor.disableUser(provider, handle)
                .onErrorResume(e -> {
                    log.warn("[casdoor] best-effort disableUser {}:{} failed: {}",
                            provider, handle, e.toString());
                    return Mono.empty();
                });
    }

    private Mono<Map<String, Object>> allowlistOut(PrincipalDomain scope) {
        Flux<String> emails = scope.scoped()
                ? store.allowedEmails(scope.domain())
                : store.allowedEmails();
        Flux<String> discord = scope.scoped()
                ? store.allowedDiscord(scope.domain())
                : store.allowedDiscord();
        return Mono.zip(emails.collectList(), discord.collectList())
                .map(t -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("emails", t.getT1());
                    out.put("discord", t.getT2());
                    return out;
                });
    }

    // ── Usage analytics (ClickHouse, in-memory fallback) ───────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Usage", operationId = "adminUsage")
    @GetMapping("/usage")
    public Mono<Map<String, Object>> usage() {
        return usage.aggregate();
    }

    // ── Grant/revoke users access to namespaces ────────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Namespace access", operationId = "adminNamespaceAccess")
    @GetMapping("/namespace-access")
    public Mono<Map<String, Object>> namespaceAccess(Authentication auth) {
        return namespaceOut(scope(auth));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Grant", operationId = "adminGrant")
    @PostMapping("/namespace-access")
    public Mono<ResponseEntity<Map<String, Object>>> grant(@Valid @RequestBody NamespaceAccessRequest b, Authentication auth) {
        String user = str(b.user());
        String namespace = str(b.namespace());
        if (user == null || namespace == null || !store.isValidNamespace(namespace)) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of("error", "user + valid namespace required")));
        }
        // Never provision (grant access to) an account whose username is a
        // reserved app path/prefix. The grantee may be a bare username or a
        // "provider:handle" id — check the handle portion either way.
        if (ReservedNames.isReserved(usernamePartOf(user))) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of(
                    "error", "user '" + user + "' has a reserved username and cannot be provisioned")));
        }
        PrincipalDomain scope = scope(auth);
        return store.grant(user, namespace, scope.domain())
                .then(Mono.fromRunnable(() -> usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.grant").subscribe()))
                .then(namespaceOut(scope))
                .map(ResponseEntity::ok);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Revoke", operationId = "adminRevoke")
    @DeleteMapping("/namespace-access")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(@Valid @RequestBody NamespaceAccessRequest b, Authentication auth) {
        String user = str(b.user());
        String namespace = str(b.namespace());
        if (user == null || namespace == null || !store.isValidNamespace(namespace)) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of("error", "user + valid namespace required")));
        }
        PrincipalDomain scope = scope(auth);
        return store.revoke(user, namespace, scope.domain()).then(namespaceOut(scope)).map(ResponseEntity::ok);
    }

    private Mono<Map<String, Object>> namespaceOut(PrincipalDomain scope) {
        Mono<List<Map<String, Object>>> grantsFlux = scope.scoped()
                ? store.allGrants(scope.domain())
                : store.allGrants();
        return grantsFlux.map(grants -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("namespaces", AccountStore.NAMESPACES);
            out.put("grants", grants);
            return out;
        });
    }

    // ── Access-role suspension (ban / timed-suspend) desired state ─────
    // The endpoints ONLY write/clear the access_suspension table + trigger a
    // reconcile tick. The single-writer reconcile loop is the SOLE caller of
    // CasdoorAdminClient.add/removeUserFromRole + the homeserver suspend seam, so a
    // clobber self-heals on the next tick (the table is the source of truth).
    // ROLE_MESH is a first-class member of this vocabulary (changeset 330): its
    // reconciler drives the Casdoor membership ONLY — there is no mesh homeserver, so
    // dropping the role makes every gateway allow-predicate on /bff/mesh/** false
    // (governed-but-ungranted -> DENY) and THAT is the ban. See MeshAccessSyncAction.
    private static final String ROLE_PATTERN = "ROLE_MATRIX|ROLE_MASTODON|ROLE_MESH|PROFILE";

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Access roles", operationId = "adminAccessRoles")
    @GetMapping("/access-roles")
    public Mono<Map<String, Object>> accessRoles(Authentication auth) {
        return suspensions.listActive(scope(auth)).collectList().map(s -> Map.of("suspensions", s));
    }

    /**
     * Suspend {@code user} from {@code role} (write an active access_suspension row +
     * reconcile). Optional body adds a TTL (auto-restore at expiry) + reason; with no
     * ttlSeconds the suspension is permanent. The {@code role} path variable is
     * @Pattern-validated to the closed vocabulary (matches the DB CHECK).
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Suspend access role", operationId = "adminSuspendAccessRole")
    @PostMapping("/access-roles/{role}/{user}")
    public Mono<ResponseEntity<Map<String, Object>>> suspendAccessRole(
            @PathVariable
            @Pattern(regexp = ROLE_PATTERN,
                    message = "role must be one of ROLE_MATRIX, ROLE_MASTODON, ROLE_MESH, PROFILE")
            String role,
            @PathVariable @NotBlank(message = "user is required")
            @Size(max = 400, message = "user is too long") String user,
            @RequestBody(required = false) @Valid SuspensionRequest body,
            Authentication auth) {
        Long ttlSeconds = body == null ? null : body.ttlSeconds();
        String reason = body == null ? null : str(body.reason());
        PrincipalDomain scope = scope(auth);
        return suspensions.suspend(role, user, ttlSeconds, reason, actor(auth), scope)
                .flatMap(s -> {
                    usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.access-suspend").subscribe();
                    return suspensions.listActive(scope).collectList().map(active -> {
                        Map<String, Object> out = new LinkedHashMap<>();
                        out.put("suspended", s);
                        out.put("suspensions", active);
                        return ResponseEntity.ok(out);
                    });
                });
    }

    /**
     * Lift the active suspension(s) for {@code user}/{@code role} (CAS
     * active->restored + reconcile so the role + homeserver state are restored). A
     * no-op if not currently suspended.
     *
     * <p>Uses {@link SuspensionService#clearByHandle} (localpart-normalized), NOT the
     * exact-string {@link SuspensionService#clear}: an admin lifting a ban may type a
     * DIFFERENT string form of the user's identity (e.g. a bare handle
     * {@code alice@x.com}) than whatever string form the ban was originally set with
     * (e.g. {@code google:alice@x.com}). An exact-string match would silently no-op —
     * the admin sees "success" while the ban stays in effect. clearByHandle matches on
     * the SAME normalized localpart {@link SuspensionService#statusFor} gates on, so
     * any valid string form of the user's identity actually clears the row.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Clear access role", operationId = "adminClearAccessRole")
    @DeleteMapping("/access-roles/{role}/{user}")
    public Mono<ResponseEntity<Map<String, Object>>> clearAccessRole(
            @PathVariable
            @Pattern(regexp = ROLE_PATTERN,
                    message = "role must be one of ROLE_MATRIX, ROLE_MASTODON, ROLE_MESH, PROFILE")
            String role,
            @PathVariable @NotBlank(message = "user is required")
            @Size(max = 400, message = "user is too long") String user,
            Authentication auth) {
        PrincipalDomain scope = scope(auth);
        return suspensions.clearByHandle(role, user, actor(auth), scope)
                .then(Mono.fromRunnable(() ->
                        usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.access-restore").subscribe()))
                .then(suspensions.listActive(scope).collectList())
                .map(active -> ResponseEntity.ok(Map.of("suspensions", active)));
    }

    // ── Domain-lock (force local-only / no-federation) desired state ───
    // The endpoints ONLY write/clear the domain_lock table + trigger a reconcile tick.
    // The single-writer reconcile loop is the SOLE caller of the homeserver force-local
    // seam + CasdoorAdminClient.add/removeUserFromRole for the *_DOMAINLOCKED MARKER
    // roles, so a clobber self-heals on the next tick (the table is the source of
    // truth, and its active set IS the force-local allowlist the generator MRF/egress
    // reads). This is ADD-semantics — the locked user KEEPS ROLE_MATRIX/ROLE_MASTODON
    // (the gateway is untouched). SEPARATE @Pattern from the suspension ROLE_PATTERN
    // (do NOT widen that closed vocabulary).
    private static final String DOMAINLOCK_ROLE_PATTERN =
            "ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED";

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Domain locks", operationId = "adminDomainLocks")
    @GetMapping("/domain-lock")
    public Mono<Map<String, Object>> domainLocks(Authentication auth) {
        return domainLocks.listActive(scope(auth)).collectList().map(l -> Map.of("domainLocks", l));
    }

    /**
     * Domain-lock {@code user} on {@code role} (write an active domain_lock row + a
     * synchronous lock-immediacy enforce + reconcile). Optional body adds a reason. The
     * {@code role} path variable is @Pattern-validated to the closed domain-locked
     * vocabulary (matches the DB CHECK).
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Lock domain", operationId = "adminLockDomain")
    @PostMapping("/domain-lock/{role}/{user}")
    public Mono<ResponseEntity<Map<String, Object>>> lockDomain(
            @PathVariable
            @Pattern(regexp = DOMAINLOCK_ROLE_PATTERN,
                    message = "role must be one of ROLE_MATRIX_DOMAINLOCKED, ROLE_MASTODON_DOMAINLOCKED")
            String role,
            @PathVariable @NotBlank(message = "user is required")
            @Size(max = 400, message = "user is too long") String user,
            @RequestBody(required = false) @Valid DomainLockRequest body,
            Authentication auth) {
        String reason = body == null ? null : str(body.reason());
        PrincipalDomain scope = scope(auth);
        return domainLocks.lock(role, user, reason, actor(auth), scope)
                .flatMap(l -> {
                    usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.domain-lock").subscribe();
                    return domainLocks.listActive(scope).collectList().map(active -> {
                        Map<String, Object> out = new LinkedHashMap<>();
                        out.put("locked", l);
                        out.put("domainLocks", active);
                        return ResponseEntity.ok(out);
                    });
                });
    }

    /**
     * Lift the active domain-lock for {@code user}/{@code role} (CAS active->removed +
     * reconcile so the force-local leg + the Casdoor marker are reversed). A no-op if
     * not currently locked.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Unlock domain", operationId = "adminUnlockDomain")
    @DeleteMapping("/domain-lock/{role}/{user}")
    public Mono<ResponseEntity<Map<String, Object>>> unlockDomain(
            @PathVariable
            @Pattern(regexp = DOMAINLOCK_ROLE_PATTERN,
                    message = "role must be one of ROLE_MATRIX_DOMAINLOCKED, ROLE_MASTODON_DOMAINLOCKED")
            String role,
            @PathVariable @NotBlank(message = "user is required")
            @Size(max = 400, message = "user is too long") String user,
            Authentication auth) {
        PrincipalDomain scope = scope(auth);
        return domainLocks.unlock(role, user, actor(auth), scope)
                .then(Mono.fromRunnable(() ->
                        usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.domain-unlock").subscribe()))
                .then(domainLocks.listActive(scope).collectList())
                .map(active -> ResponseEntity.ok(Map.of("domainLocks", active)));
    }

    // ── Appeals adjudication (proxy to federation-api) ─────────────────
    // The admin-ui appeals console's DECIDE action: approve / deny a referred
    // moderation request. The admin-bff does NOT own moderation_requests — it proxies
    // to hugmesh-federation-api's POST /api/federation/moderation/{id}/decide,
    // forwarding the caller's Casdoor JWT so federation-api applies its OWN
    // @PreAuthorize(ADMIN/SUPERADMIN) + per-domain scope (a brand-X admin's token
    // carries brand-X's issuer, so federation-api scopes the decide to brand X and a
    // brand-Y row is invisible/404 — cross-domain DENY enforced downstream). The
    // admin-bff re-applies hasRole('ADMIN') here as DEFENCE-IN-DEPTH (on top of the
    // gateway route-access rule + the /bff/admin/** path rule); the {id} path var is
    // @Positive-validated so a non-numeric id is a clean 400 before the proxy call.
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Decide moderation", operationId = "adminDecideModeration")
    @PostMapping("/moderation/{id}/decide")
    public Mono<ResponseEntity<ModerationDecisionDto>> decideModeration(
            @PathVariable @Positive(message = "id must be a positive number") Long id,
            @RequestParam boolean approve,
            Authentication auth) {
        return federation.decide(id, approve)
                .doOnSuccess(decided -> usage.record(actor(auth), List.of(RoleName.ADMIN.value()),
                        approve ? "admin.appeal-approve" : "admin.appeal-deny").subscribe())
                .map(ResponseEntity::ok)
                // A downstream failure (federation-api unreachable / non-2xx) surfaces
                // as a clean 502 {error} rather than a leaked 500, matching the BFF's
                // existing badGateway shape for proxied calls.
                .onErrorResume(e -> e instanceof ApiException
                        ? Mono.error(e)
                        : Mono.error(ApiException.badGateway(String.valueOf(e))));
    }

    // ── Per-gateway role->URL external-access rules ────────────────────
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Route access", operationId = "adminRouteAccess")
    @GetMapping("/route-access")
    public Mono<Map<String, Object>> routeAccess(Authentication auth) {
        return routeAccess.list(scope(auth)).collectList().map(rules -> Map.of("rules", rules));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Add route rule", operationId = "adminAddRouteRule")
    @PostMapping("/route-access")
    public Mono<ResponseEntity<Map<String, Object>>> addRouteRule(@Valid @RequestBody RouteRuleRequest b, Authentication auth) {
        String gateway = str(b.gateway());
        String urlPattern = str(b.urlPattern());
        String role = str(b.role());
        if (gateway == null || urlPattern == null || role == null) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of("error", "gateway+url_pattern+role required")));
        }
        // Reserved-prefix invariant: the rule's URL pattern must resolve to a
        // usable first path segment (reject a pattern that is only '/' or a
        // bare wildcard — it can't target a dedicated prefix). When the first
        // segment is a NEW dedicated prefix not yet in the reserved set, the
        // reserved list (the username-collision source of truth) is out of
        // date — warn so it gets added, but don't block an access-rule change.
        String firstSegment = ReservedNames.firstSegment(urlPattern);
        if (firstSegment.isEmpty() && !"/".equals(urlPattern)) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of(
                    "error", "url_pattern '" + urlPattern + "' has no addressable first path segment")));
        }
        String reservedWarning = reservedPrefixWarning(firstSegment);
        boolean allow = !Boolean.FALSE.equals(b.allow());   // defaults true (null -> true)
        // Per-row MFA flag (dual-write trio): OPTIONAL, defaults false (null -> false). admin-bff
        // persists it for consistency with the gateway/generator; the gateway is the sole enforcer.
        boolean mfaRequired = Boolean.TRUE.equals(b.mfaRequired());
        PrincipalDomain scope = scope(auth);
        // Stamp the acting principal's brand on the new rule so it lands in their
        // tenant; a scoped admin can never create a rule in another brand.
        return routeAccess.add(new RouteRule(null, gateway, urlPattern, role, str(b.casdoorUser()),
                        allow, scope.domain(), mfaRequired))
                // Record usage then return the current rule list with the newly added rule.
                .flatMap(added -> buildRouteRuleResponse(added, scope, auth, reservedWarning));
    }

    /** Collect the current rule list and compose the addRouteRule response body. */
    private Mono<ResponseEntity<Map<String, Object>>> buildRouteRuleResponse(
            RouteRule added, PrincipalDomain scope, Authentication auth, String reservedWarning) {
        usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.route").subscribe();
        return routeAccess.list(scope).collectList()
                .map(rules -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("rules", rules);
                    out.put("added", added);
                    if (reservedWarning != null) out.put("reservedWarning", reservedWarning);
                    return ResponseEntity.ok(out);
                });
    }

    /**
     * If {@code firstSegment} is a non-empty dedicated route prefix that is
     * NOT in {@link ReservedNames#RESERVED}, return a warning telling the
     * admin to add it to the reserved set (so a username can never later be
     * created that shadows this new route). Returns null when the segment is
     * blank or already reserved (the common, consistent case).
     */
    private static String reservedPrefixWarning(String firstSegment) {
        if (firstSegment.isEmpty() || ReservedNames.isReserved(firstSegment)) return null;
        // Point at the REAL sync chain: the canonical set is the generator's
        // specs/cluster/reserved-prefixes.yaml; the code copies are
        // hugmesh-auth-core's ReservedNames (the shared library this BFF and
        // user-bff consume — this repo's local duplicate was deleted in favour of
        // it) plus the literal duplicates in hugmesh-actions and
        // hugmesh-federation-api. The previous text told operators to edit a
        // copy "in hugmesh-admin-bff-api", which no longer exists.
        String msg = "route prefix '" + firstSegment + "' is NOT in the reserved username list; "
                + "add it to the canonical reserved-prefixes.yaml (generator) and the ReservedNames "
                + "copies (hugmesh-auth-core, hugmesh-actions, hugmesh-federation-api) "
                + "so a username can never be created that shadows this route";
        log.warn("[reserved] {}", msg);
        return msg;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Remove route rule", operationId = "adminRemoveRouteRule")
    @DeleteMapping("/route-access")
    public Mono<Map<String, Object>> removeRouteRule(@Valid @RequestBody RouteRuleDeleteRequest b,
                                                     Authentication auth) {
        // @Pattern guarantees a UUID-shaped id here, so RouteAccessRepository.delete's
        // UUID.fromString can never throw (which would have been an uncaught 500). The
        // delete is DOMAIN-SCOPED: a scoped admin can only delete a rule in their own
        // brand (another brand's id is a no-op for them); SUPERADMIN deletes any id.
        return routeAccess.remove(b.id(), scope(auth)).collectList().map(rules -> Map.of("rules", rules));
    }

    // ── DB-driven gateway ROUTE DEFINITIONS (url_registry) ───────────
    // SUPERADMIN-only: the url_registry Cassandra table has no domain column
    // (path_prefix is the sole PK), so it is a CLUSTER-LEVEL resource shared
    // across all brand gateways. A brand-scoped ADMIN could overwrite another
    // brand's route definitions or expose its routes to other brands — a
    // cross-tenant BFLA. Route DEFINITIONS are infrastructure; brand admins
    // use route-ACCESS rules (/bff/admin/route-access, domain-scoped in Postgres).
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Routes", operationId = "adminRoutes")
    @GetMapping("/routes")
    public Mono<Map<String, Object>> routes() {
        return urlRegistry.list().collectList().map(routes -> Map.of("routes", routes));
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Upsert route", operationId = "adminUpsertRoute")
    @PostMapping("/routes")
    public Mono<ResponseEntity<Map<String, Object>>> upsertRoute(@Valid @RequestBody UrlRouteRequest b) {
        String pathPrefix = str(b.pathPrefix());
        String downstreamUri = str(b.downstreamUri());
        if (pathPrefix == null || downstreamUri == null) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of("error", "pathPrefix + downstreamUri required")));
        }
        // A route DEFINITION is where a NEW dedicated prefix is actually
        // introduced. Its first segment must be addressable, and if it is a
        // new prefix not yet in the reserved set we warn (the reserved list is
        // the username-collision source of truth and must gain this prefix).
        String firstSegment = ReservedNames.firstSegment(pathPrefix);
        if (firstSegment.isEmpty() && !"/".equals(pathPrefix)) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of(
                    "error", "pathPrefix '" + pathPrefix + "' has no addressable first path segment")));
        }
        String reservedWarning = reservedPrefixWarning(firstSegment);
        return urlRegistry.upsert(new UrlRoute(pathPrefix, downstreamUri,
                        str(b.serviceName()), str(b.requiredRole()), b.stripPrefix()))
                .flatMap(saved -> urlRegistry.list().collectList()
                        .map(routes -> {
                            Map<String, Object> out = new LinkedHashMap<>();
                            out.put("routes", routes);
                            out.put("upserted", saved);
                            if (reservedWarning != null) out.put("reservedWarning", reservedWarning);
                            return ResponseEntity.ok(out);
                        }));
    }

    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Remove route", operationId = "adminRemoveRoute")
    @DeleteMapping("/routes/{pathPrefix}")
    public Mono<Map<String, Object>> removeRoute(
            @PathVariable
            @NotBlank(message = "pathPrefix is required")
            @Size(max = 512, message = "pathPrefix is too long")
            String pathPrefix) {
        return urlRegistry.remove(pathPrefix).collectList().map(routes -> Map.of("routes", routes));
    }

    // ── Latest delivered ISO artifacts (download links for the admin UI) ──
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Isos", operationId = "adminIsos")
    @GetMapping("/isos")
    public Mono<Map<String, Object>> isos() {
        return isoRepo.list().collectList().map(isos -> Map.of("isos", isos));
    }

    // ── Standalone Casdoor role grant / revoke ─────────────────────────
    // DIRECT grant/revoke — calls CasdoorAdminClient.add/removeUserFromRole and
    // returns immediately. Does NOT write an access_suspension row and does NOT
    // involve the reconcile loop or homeserver seams. Use for one-shot capability
    // grants/revocations (e.g. ROLE_MATRIX, ROLE_GAMES, ROLE_IMAGE_BUILDER) that
    // carry no timed-ban or homeserver-restore semantics. For timed bans with
    // homeserver-seam effect, use POST /access-roles/{role}/{user} instead.
    //
    // The vocabulary is closed: only the listed platform-access + capability roles
    // are grantable. Service/bootstrap roles (ROLE_SUPERADMIN, ROLE_GATEWAY,
    // ROLE_API, ROLE_ADMIN_API, ROLE_SERVICE) are NOT in this set — they can only
    // be assigned via the generator / Casdoor init_data seed.
    private static final String GRANTABLE_ROLE_PATTERN =
            "ROLE_USER|ROLE_MOD|ROLE_ADMIN|ROLE_MATRIX|ROLE_MASTODON|ROLE_GAMES|ROLE_GAMES_ADMIN|"
            + "ROLE_IMAGE_BUILDER|ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED|"
            + "ROLE_MATRIX_EXTERNAL_CLIENT|ROLE_MASTODON_EXTERNAL_CLIENT|ROLE_FLEET_ADMIN";

    /**
     * Grant {@code roleName} to {@code user} in Casdoor (direct add-to-role call,
     * bypassing the suspension reconcile loop). The {@code user} parameter is the
     * Casdoor username within the configured organization. Returns 503 when the
     * Casdoor admin client is not enabled.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Grant role", operationId = "adminGrantRole")
    @PostMapping("/roles/{roleName}/{user}")
    public Mono<ResponseEntity<Map<String, Object>>> grantRole(
            @PathVariable
            @Pattern(regexp = GRANTABLE_ROLE_PATTERN,
                    message = "roleName must be a grantable platform-access or capability role")
            String roleName,
            @PathVariable @NotBlank(message = "user is required")
            @Size(max = 400, message = "user is too long") String user,
            Authentication auth) {
        if (casdoor == null) {
            return Mono.just(ResponseEntity.status(503).<Map<String, Object>>body(
                    Map.of("error", "Casdoor admin client not enabled (casdoor.admin.enabled=false)")));
        }
        return casdoor.addUserToRole(roleName, casdoor.organization() + "/" + user)
                // Invalidate the grantee's live custody JWT so the NEW role is picked up
                // on the next (re-minted) token rather than only after the natural TTL
                // (~1 h). Best-effort + gated on broker.gateway-revocation.enabled — a
                // no-op in dev. Symmetric with revokeRole (closes the G2 inverse-stale gap).
                .then(revocations.revokeSubject(user, "role-grant", 3_600L))
                .then(Mono.fromRunnable(() ->
                        usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.role-grant").subscribe()))
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of("granted", roleName, "user", user)));
    }

    /**
     * Revoke {@code roleName} from {@code user} in Casdoor (direct remove-from-role
     * call, bypassing the suspension reconcile loop). The {@code user} parameter is
     * the Casdoor username within the configured organization. Returns 503 when the
     * Casdoor admin client is not enabled.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Revoke role", operationId = "adminRevokeRole")
    @DeleteMapping("/roles/{roleName}/{user}")
    public Mono<ResponseEntity<Map<String, Object>>> revokeRole(
            @PathVariable
            @Pattern(regexp = GRANTABLE_ROLE_PATTERN,
                    message = "roleName must be a grantable platform-access or capability role")
            String roleName,
            @PathVariable @NotBlank(message = "user is required")
            @Size(max = 400, message = "user is too long") String user,
            Authentication auth) {
        if (casdoor == null) {
            return Mono.just(ResponseEntity.status(503).<Map<String, Object>>body(
                    Map.of("error", "Casdoor admin client not enabled (casdoor.admin.enabled=false)")));
        }
        return casdoor.removeUserFromRole(roleName, casdoor.organization() + "/" + user)
                // Invalidate any live custody JWT for this user so the revoked role
                // cannot be exercised for the remaining natural TTL (~1 h). Best-effort
                // + gated on broker.gateway-revocation.enabled — a no-op in dev.
                .then(revocations.revokeSubject(user, "role-revoke", 3_600L))
                .then(Mono.fromRunnable(() ->
                        usage.record(actor(auth), List.of(RoleName.ADMIN.value()), "admin.role-revoke").subscribe()))
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of("revoked", roleName, "user", user)));
    }

    /** The acting admin's identity for usage attribution (JWT subject/name). */
    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }

    /**
     * The username/handle portion of a grantee identifier. Grantees are
     * stored either as a bare username or as a {@code provider:handle} id
     * (e.g. {@code discord:alice}); the reserved check applies to the handle,
     * so split off any leading {@code provider:} segment.
     */
    private static String usernamePartOf(String user) {
        if (user == null) return null;
        int colon = user.indexOf(':');
        return colon >= 0 ? user.substring(colon + 1) : user;
    }

    /** Null-or-blank-safe String coercion for request-body map values. */
    private static String str(Object o) {
        if (o == null) return null;
        String s = o.toString().trim();
        return s.isEmpty() ? null : s;
    }
}
